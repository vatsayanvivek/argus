package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// personalisationContext holds the environment-specific facts that the
// chain narrative personaliser uses to substitute placeholders. Each
// field is computed once per scan in buildPersonalisationContext.
//
// The goal: stop the chain narratives from sounding like a generic
// "an attacker compromises X and pivots to Y" template and start
// sounding like "an attacker compromises THE 13 App Registrations
// in YOUR tenant ('FS-Orchestration', 'GitHub Cloud', ...) holding
// dangerous Graph permissions and pivots to YOUR storage account
// 'nxstrprodwus2tfstate' which has network defaults set to Allow."
//
// All resource references come from the actual finding instances so
// the customer reading the report sees their own resource names,
// resource group names, tenant IDs, and user counts woven into the
// attacker narrative.
type personalisationContext struct {
	subscriptionName     string
	tenantID             string
	usersWithoutMFA      int
	totalUsers           int
	totalAppRegs         int
	dangerousAppRegs     []string // display names of App Regs with dangerous Graph perms
	publicNSGCount       int
	publicStorageCount   int
	publicAKSCount       int
	defenderFreeServices []string // service names on Free tier
	noPIM                bool
	noCAP                bool
	legacyAuth           bool
	resourcesByRule      map[string][]string // rule_id → []resource_name
}

// buildPersonalisationContext walks the snapshot and finding map once
// and pulls out the values used to rewrite chain narratives.
func buildPersonalisationContext(
	snapshot *models.AzureSnapshot,
	findingMap map[string][]models.Finding,
) *personalisationContext {
	ctx := &personalisationContext{
		resourcesByRule: map[string][]string{},
	}
	if snapshot == nil {
		return ctx
	}

	ctx.subscriptionName = snapshot.SubscriptionName
	if ctx.subscriptionName == "" {
		ctx.subscriptionName = "your subscription"
	}
	ctx.tenantID = snapshot.TenantID

	// Identity stats: total users, users without MFA.
	ctx.totalUsers = len(snapshot.Identity.Users)
	for _, u := range snapshot.Identity.Users {
		if u.AccountEnabled && u.UserType == "Member" && !u.MFAEnabled {
			ctx.usersWithoutMFA++
		}
	}
	ctx.totalAppRegs = len(snapshot.Identity.AppRegistrations)

	// Tenant settings.
	ts := snapshot.Identity.TenantSettings
	ctx.legacyAuth = ts.LegacyAuthEnabled
	ctx.noCAP = len(snapshot.Identity.ConditionalAccess) == 0
	ctx.noPIM = len(snapshot.Identity.PIMAssignments) == 0

	// Defender plans on Free tier.
	for service, plan := range snapshot.DefenderPlans {
		if strings.EqualFold(plan, "Free") {
			ctx.defenderFreeServices = append(ctx.defenderFreeServices, service)
		}
	}
	sort.Strings(ctx.defenderFreeServices)

	// Build rule_id → resource name list. This is the main lookup
	// table the personaliser uses to weave real resources into the
	// narrative for each chain.
	for ruleID, list := range findingMap {
		seen := map[string]bool{}
		for _, f := range list {
			name := f.ResourceName
			if name == "" {
				name = f.ResourceID
			}
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			ctx.resourcesByRule[ruleID] = append(ctx.resourcesByRule[ruleID], name)
		}
	}

	// Top-level counts of "dangerous" categories the chains mention.
	ctx.publicNSGCount = len(findingMap["zt_net_001"]) + len(findingMap["zt_net_002"]) +
		len(findingMap["cis_6_1"]) + len(findingMap["cis_6_2"])
	ctx.publicStorageCount = len(findingMap["zt_data_001"]) + len(findingMap["cis_3_3"])
	ctx.publicAKSCount = len(findingMap["zt_wl_003"])

	// App Registration display names from cis_1_15 / zt_id_011 findings.
	appRegSet := map[string]bool{}
	for _, ruleID := range []string{"zt_id_011", "cis_1_15"} {
		for _, f := range findingMap[ruleID] {
			name := f.ResourceName
			if name != "" && !appRegSet[name] {
				appRegSet[name] = true
				ctx.dangerousAppRegs = append(ctx.dangerousAppRegs, name)
			}
		}
	}
	sort.Strings(ctx.dangerousAppRegs)

	return ctx
}

// personaliseChain rewrites a chain's Narrative and EnvironmentSummary
// to weave in real environment data. It is called once per chain
// after the builder has produced the generic template.
//
// Strategy: for each chain ID we know which environment facts are
// most relevant. We append a "In YOUR environment:" sentence to the
// existing narrative that names specific resources, counts, and
// affected user populations. The original narrative stays as the
// "attacker perspective" intro and the personalised sentence becomes
// the "what this means for YOU" closing.
func personaliseChain(chain *models.AttackChain, ctx *personalisationContext, findingMap map[string][]models.Finding) {
	if chain == nil || ctx == nil {
		return
	}

	// Build a chain-specific customisation sentence.
	custom := customisationFor(chain.ID, ctx, findingMap)
	if custom == "" {
		return
	}

	// Append it to the existing narrative as a separate paragraph.
	chain.Narrative = strings.TrimSpace(chain.Narrative) + "\n\nIn YOUR environment: " + custom

	// Also tighten the EnvironmentSummary if it's empty or generic.
	if chain.EnvironmentSummary == "" || strings.HasPrefix(chain.EnvironmentSummary, "In your subscription") {
		chain.EnvironmentSummary = environmentSummaryFor(chain.ID, ctx, findingMap)
	}
}

// customisationFor returns the chain-specific "in YOUR environment"
// sentence that gets appended to the narrative. Each chain has its own
// template that pulls the most relevant facts from the personalisation
// context.
func customisationFor(chainID string, ctx *personalisationContext, fm map[string][]models.Finding) string {
	switch chainID {
	case "CHAIN-001":
		// Internet-exposed VM → wildcard IAM
		nsgs := joinTop(ctx.resourcesByRule["zt_net_001"], 3)
		if nsgs == "" {
			nsgs = joinTop(ctx.resourcesByRule["zt_net_002"], 3)
		}
		if nsgs == "" {
			return ""
		}
		return fmt.Sprintf(
			"%s exposes RDP/SSH on %s and the VMs behind those NSGs use service-principal credentials stored on disk instead of managed identity. "+
				"An attacker who walks in through the open management port finds those credentials in cleartext and uses them to call ARM with subscription-level rights.",
			ctx.subscriptionName, nsgs)

	case "CHAIN-002":
		// App Reg Graph perms + storage default Allow + legacy auth
		if len(ctx.dangerousAppRegs) == 0 {
			return ""
		}
		appList := joinTop(ctx.dangerousAppRegs, 5)
		more := ""
		if len(ctx.dangerousAppRegs) > 5 {
			more = fmt.Sprintf(" (and %d more)", len(ctx.dangerousAppRegs)-5)
		}
		return fmt.Sprintf(
			"%d App Registrations in your tenant — %s%s — hold tenant-wide Microsoft Graph application permissions. "+
				"Anyone who phishes a developer who owns one of these apps gets the same blast radius as a Global Administrator. "+
				"This is the chain Defender for Cloud rates 'medium' for each App Reg in isolation; ARGUS finds it because it correlates the App Reg perms with the lack of restrictive Conditional Access on the same tenant.",
			len(ctx.dangerousAppRegs), appList, more)

	case "CHAIN-003":
		// Legacy auth + no CAP + permanent privileged
		bits := []string{}
		if ctx.legacyAuth {
			bits = append(bits, "legacy authentication is enabled tenant-wide")
		}
		if ctx.noCAP {
			bits = append(bits, "there are no enabled Conditional Access policies")
		}
		if ctx.noPIM {
			bits = append(bits, "all privileged role assignments are permanent (no PIM eligible-only)")
		}
		if len(bits) == 0 {
			return ""
		}
		return fmt.Sprintf("In your tenant, %s. A single phished credential authenticated over IMAP/SMTP basic auth bypasses every CAP rule and lands on a permanently-active Owner role assignment.", joinNatural(bits))

	case "CHAIN-004", "CHAIN-019":
		// Permanent privileged + no PIM + no reviews / no alerting
		count := len(fm["zt_id_003"])
		if count == 0 {
			return ""
		}
		return fmt.Sprintf("Your tenant has %d permanent privileged role assignments and zero PIM eligible assignments. There are also no access reviews or alert rules on Microsoft.Authorization/roleAssignments/write — meaning a permission grant in your tenant goes unnoticed indefinitely.", count)

	case "CHAIN-005":
		// Public storage + no diag + no encryption
		stors := joinTop(ctx.resourcesByRule["zt_data_001"], 3)
		if stors == "" {
			stors = joinTop(ctx.resourcesByRule["cis_3_3"], 3)
		}
		if stors == "" {
			return ""
		}
		return fmt.Sprintf("Storage accounts %s allow public blob access AND have no diagnostic settings forwarding to Log Analytics. An attacker enumerating Azure-hosted blobs would find these and exfiltrate them with zero log trail of who connected, when, or what they read.", stors)

	case "CHAIN-006":
		// AKS public + privileged containers + no KV protection
		aks := joinTop(ctx.resourcesByRule["zt_wl_003"], 2)
		if aks == "" {
			return ""
		}
		return fmt.Sprintf("AKS cluster(s) %s expose the Kubernetes API server to the internet without an authorised IP allowlist, AND admit privileged container specs. A red-team scan finds the API server, deploys a privileged pod, and uses it to mount the host filesystem.", aks)

	case "CHAIN-007":
		// No NSG on subnet + no flow logs + no Network Watcher
		return "Several subnets in your VNets have no NSG attached at all, and NSG flow logs are not enabled anywhere. Lateral movement between any two workloads inside the VNet is invisible — there is no record of who talked to whom."

	case "CHAIN-008":
		// Defender free + open ports / Sentinel missing
		freeList := joinTop(ctx.defenderFreeServices, 4)
		nsgs := joinTop(ctx.resourcesByRule["zt_net_001"], 2)
		if nsgs == "" {
			nsgs = joinTop(ctx.resourcesByRule["zt_net_002"], 2)
		}
		if freeList == "" && nsgs == "" {
			return ""
		}
		return fmt.Sprintf("Microsoft Defender for Cloud is on the Free tier for %s, AND %s exposes management ports to the internet. Even if an attacker brute-forces RDP on those NSGs, the lack of Defender Standard means there is no behavioural detection of the post-exploitation activity.", freeList, nsgs)

	case "CHAIN-009":
		// KV no protection + no alerts → ransomware
		return "One or more Key Vaults have purge protection disabled and no action group alerts on vault operations. An attacker (or rogue admin) can soft-delete and then purge a vault containing your TDE keys — and you would only find out when applications start failing."

	case "CHAIN-010":
		// SQL no PE + Allow Azure IPs + no audit
		return "An Azure SQL logical server has no Private Endpoint, its firewall rule allows the entire Azure IP space (0.0.0.0–255.255.255.255), and SQL Auditing is not enabled. Any compromised Azure tenant in the world can attempt connections to it, and you would have no audit trail of the attempts."

	case "CHAIN-011":
		// Cross-tenant unrestricted + no CAP + activity log gap
		if !ctx.noCAP {
			return ""
		}
		return "Your tenant has cross-tenant access set to allow inbound from any Microsoft Entra tenant AND no Conditional Access policy filters by signing tenant. A user from any Microsoft Entra tenant in the world can authenticate against your apps as a guest and the activity log retention is too short to backdate the investigation."

	case "CHAIN-012":
		// Function no auth + system identity + no diag
		return "A Function App has no authentication configured (anonymous invocation allowed) AND uses a system-assigned managed identity that has been granted Contributor on the resource group. The function code becomes a no-auth API gateway to the resource group's worth of Azure resources."

	case "CHAIN-013":
		// VNet peering + no NVA + no NSG flow logs
		return "Your hub VNet is peered to multiple spoke VNets but there is no Azure Firewall or NVA filtering inter-spoke traffic, AND NSG flow logs are not enabled. East-west movement between spokes is unconstrained and unmonitored."

	case "CHAIN-014":
		// VM no backup + public storage + storage allow all
		return "A VM has no backup policy in any Recovery Services Vault, the storage account holding its disk allows public blob access, and the storage network default action is Allow. A ransomware actor can encrypt the disk and there is no clean backup to restore from."

	case "CHAIN-015":
		// App Service HTTP + remote debug + secret near expiry
		return "An App Service runs on plain HTTP, has remote debugging enabled, and has a Key Vault secret expiring within 30 days. An attacker on the same network captures the credential during a debug session before the secret rotates."

	case "CHAIN-016":
		// No JIT + open ports + no role-change alerts
		nsgs := joinTop(ctx.resourcesByRule["zt_net_001"], 2)
		return fmt.Sprintf("Just-in-time VM access is not configured on any VM, %s exposes RDP/SSH continuously, AND there are no activity log alerts on role assignment writes. An attacker who establishes persistence has unlimited dwell time.", nsgs)

	case "CHAIN-017":
		// Guest unrestricted + no reviews + no critical-op alerts
		return "Guest user permissions are unrestricted in your tenant, no access reviews exist on guest accounts, and there are no activity log alerts on critical operations like role assignments. Any guest invited a year ago still has access today and you have no record of when they last used it."

	case "CHAIN-018":
		// No WAF + no DDoS + no vuln assessment
		return "An Application Gateway sits in front of public-facing apps without a WAF policy attached, the VNet has no DDoS Protection Standard plan, and the backend VMs have no vulnerability assessment extension. The first L7 attack against any of these apps will succeed and you will not even know what was vulnerable."

	case "CHAIN-020":
		// No Sentinel + no diagnostics + low retention
		return "Your tenant has no Microsoft Sentinel workspace deployed, several security-relevant resources have no diagnostic settings forwarding logs anywhere, AND the activity log retention is below 90 days. A breach today would have no forensic trail tomorrow."

	case "CHAIN-021":
		// Public registry + AKS public + privileged containers
		return "An AKS cluster pulls images from a public container registry instead of a private ACR, the cluster API server is internet-reachable, and pod security admission allows privileged specs. A supply-chain compromise of any base image you depend on lands directly inside your cluster."

	case "CHAIN-022":
		// Emergency access lockout to tenant takeover
		return "Your tenant has no emergency access (break-glass) accounts, admin roles do not require phishing-resistant authentication strength, and PIM role activation has no approval workflow. If an attacker compromises a single admin credential, they can elevate to Global Administrator without anyone approving the activation — and with no break-glass account, your organisation cannot recover control of the tenant."

	case "CHAIN-023":
		// Conditional Access bypass to identity harvest
		count := ctx.usersWithoutMFA
		if count == 0 {
			return ""
		}
		return fmt.Sprintf("Conditional Access policies do not define named locations, sign-in risk evaluation is disabled, and MFA registration is not enforced. %d users in your tenant have no MFA configured — an attacker can authenticate as any of them from any IP address and no risk signal will fire.", count)

	case "CHAIN-024":
		// Cross-tenant trust abuse to data access
		cosmos := joinTop(ctx.resourcesByRule["zt_data_011"], 3)
		if cosmos == "" {
			return ""
		}
		return fmt.Sprintf("Default cross-tenant access settings trust external tenants for MFA and device compliance claims, guest users hold directory roles, and Cosmos DB accounts %s accept traffic from all networks. An invited guest from a compromised external tenant satisfies your Conditional Access controls using their home-tenant MFA and reads your Cosmos data directly.", cosmos)

	case "CHAIN-025":
		// AKS cluster full compromise
		aks := joinTop(ctx.resourcesByRule["zt_wl_014"], 2)
		if aks == "" {
			aks = joinTop(ctx.resourcesByRule["zt_wl_015"], 2)
		}
		if aks == "" {
			return ""
		}
		return fmt.Sprintf("AKS cluster(s) %s have no network policy engine, use local Kubernetes RBAC instead of Azure RBAC, and do not enforce pod security standards. Any pod-to-pod communication is unrestricted, and an attacker who compromises one workload can escalate to cluster-admin through the local RBAC system.", aks)

	case "CHAIN-026":
		// Container registry takeover to supply chain
		acr := joinTop(ctx.resourcesByRule["zt_wl_012"], 2)
		if acr == "" {
			acr = joinTop(ctx.resourcesByRule["zt_wl_013"], 2)
		}
		if acr == "" {
			return ""
		}
		return fmt.Sprintf("Container registry %s has the admin account enabled AND allows public network access, while Defender for Containers is not monitoring the pulling AKS clusters. The admin credentials are a shared secret that any developer or CI pipeline with registry access can leak.", acr)

	case "CHAIN-027":
		// App Service remote debug to internal pivot
		apps := joinTop(ctx.resourcesByRule["zt_wl_018"], 3)
		if apps == "" {
			return ""
		}
		return fmt.Sprintf("App Service(s) %s have remote debugging enabled, their subnets have no NSG, and Application Insights is not configured. An attacker who attaches a debugger gains code execution with the app's identity and can move laterally through the unprotected subnet without any APM-level detection.", apps)

	case "CHAIN-028":
		// Key Vault silent breach and purge
		kv := joinTop(ctx.resourcesByRule["zt_data_014"], 3)
		if kv == "" {
			return ""
		}
		return fmt.Sprintf("Key Vault(s) %s have purge protection disabled and no diagnostic logging configured. Service principal credentials older than 90 days are in use. An attacker with a stale credential can read every secret, soft-delete the vault, then purge it — and there are zero logs of what was accessed.", kv)

	case "CHAIN-029":
		// SQL invisible exfiltration
		sql := joinTop(ctx.resourcesByRule["zt_data_012"], 3)
		if sql == "" {
			return ""
		}
		return fmt.Sprintf("SQL Server(s) %s do not have auditing enabled, audit log retention is under 90 days, and TDE uses service-managed keys instead of customer-managed. An attacker who gains access exfiltrates data with no audit trail, and the service-managed encryption means Microsoft holds the key — not you.", sql)

	case "CHAIN-030":
		// Storage ransomware with no recovery
		stor := joinTop(ctx.resourcesByRule["zt_data_013"], 3)
		if stor == "" {
			stor = joinTop(ctx.resourcesByRule["zt_data_017"], 3)
		}
		if stor == "" {
			return ""
		}
		return fmt.Sprintf("Storage accounts %s have no blob soft delete, no blob versioning, and no Azure Backup policy. A ransomware actor (or disgruntled insider) who deletes or overwrites blobs leaves you with zero recovery options — the data is gone permanently.", stor)

	case "CHAIN-031":
		// Network perimeter collapse
		return "Your subscription has no Azure Firewall deployed, subnets exist without any NSG association, and NSGs that do exist allow unrestricted outbound traffic. There is no centralized network filtering, no micro-segmentation, and no egress control — an attacker who lands anywhere in the VNet moves freely and exfiltrates to any internet destination."

	case "CHAIN-032":
		// Web app exploitation with no WAF
		gw := joinTop(ctx.resourcesByRule["zt_net_014"], 2)
		if gw == "" {
			return ""
		}
		return fmt.Sprintf("Application Gateway %s has no WAF policy, backend apps run outdated runtimes, and Application Insights is absent. Web exploitation attempts pass through unfiltered, hit known CVEs, and generate no application-layer telemetry.", gw)

	case "CHAIN-033":
		// PIM abuse to silent privilege escalation
		return "PIM role activation requires no approval, the Activity Log is not exported to Log Analytics, and access token lifetimes exceed the secure threshold. An attacker who compromises an eligible identity self-approves Global Administrator, and the activation event is never aggregated into a query-able workspace."

	case "CHAIN-034":
		// Guest account lateral movement
		guests := joinTop(ctx.resourcesByRule["zt_id_016"], 3)
		if guests == "" {
			return ""
		}
		return fmt.Sprintf("Guest accounts %s hold directory roles, cross-tenant access defaults trust inbound MFA claims, and Conditional Access does not restrict by named location. A guest from a compromised external tenant authenticates with their home-tenant MFA and inherits your directory privileges.", guests)

	case "CHAIN-035":
		// Cognitive Services API abuse
		cog := joinTop(ctx.resourcesByRule["zt_data_020"], 3)
		if cog == "" {
			return ""
		}
		return fmt.Sprintf("Cognitive Services accounts %s allow public network access, no Azure Firewall exists for centralized traffic filtering, and no Log Analytics workspace is configured. An attacker with a leaked API key can abuse your AI/ML endpoints from the internet with no detection.", cog)

	case "CHAIN-036":
		// Service Bus message interception
		sb := joinTop(ctx.resourcesByRule["zt_data_019"], 2)
		if sb == "" {
			return ""
		}
		return fmt.Sprintf("Service Bus namespace(s) %s allow public network access, Event Hub namespaces use Microsoft-managed encryption keys, and storage diagnostic logging is disabled. Message streams are exposed to the internet without customer-controlled encryption and without an audit trail of access.", sb)

	case "CHAIN-037":
		// VPN downgrade to network intrusion
		return "VPN Gateways are not enforcing IKEv2, Network Watcher is not deployed in all regions with virtual networks, and VNet peering allows forwarded traffic. Cryptographic downgrade to IKEv1 exposes the tunnel to known attacks, traffic pivots through peers, and no packet-level monitoring covers the gap."

	case "CHAIN-038":
		// Front Door exploit chain
		fd := joinTop(ctx.resourcesByRule["zt_net_017"], 2)
		if fd == "" {
			return ""
		}
		return fmt.Sprintf("Front Door %s has no WAF policy on its frontend endpoints, the backing VNet lacks DDoS Protection Standard, and App Services do not require client certificates. Layer-7 attacks pass through Front Door unfiltered, and without mutual TLS the attacker needs no certificate to reach the backend.", fd)

	case "CHAIN-039":
		// AKS secrets exposure to data breach
		aks := joinTop(ctx.resourcesByRule["zt_wl_022"], 2)
		if aks == "" {
			aks = joinTop(ctx.resourcesByRule["zt_wl_014"], 2)
		}
		if aks == "" {
			return ""
		}
		return fmt.Sprintf("AKS cluster(s) %s do not use the Key Vault CSI driver, meaning secrets are stored in Kubernetes Secrets or environment variables. Without network policies, any compromised pod can read these secrets — and Key Vault has no purge protection, so the attacker can destroy the original secrets after exfiltrating them.", aks)

	case "CHAIN-040":
		// Identity protection gap to account takeover
		count := ctx.usersWithoutMFA
		return fmt.Sprintf("Sign-in risk and user risk policies are both disabled in Identity Protection, and SSPR allows weak authentication methods like email and security questions. Password-spray attacks generate no risk events, compromised accounts are never flagged, and attackers can reset passwords using weak factors. %d users have no MFA configured.", count)

	case "CHAIN-041":
		// Complete visibility blind spot
		return fmt.Sprintf("In %s, there is no Log Analytics workspace, the Activity Log is not exported to any external sink, and no action groups are configured. Security events are generated but never aggregated, alerts cannot fire, and no one receives notifications. This is a complete visibility black hole.", ctx.subscriptionName)

	case "CHAIN-042":
		// VM disk theft to offline data exfil
		vms := joinTop(ctx.resourcesByRule["zt_wl_020"], 3)
		if vms == "" {
			return ""
		}
		return fmt.Sprintf("VM disks on %s are not encrypted, no Azure Backup policy protects them, and no alert rules are configured. An attacker with snapshot permissions can copy unencrypted disks to an external subscription and mount them offline — and no alert fires when the snapshot is created.", vms)

	case "CHAIN-043":
		// Firewall threat intel bypass to C2
		fw := joinTop(ctx.resourcesByRule["zt_net_012"], 2)
		if fw == "" {
			return ""
		}
		return fmt.Sprintf("Azure Firewall %s has threat intelligence in Alert mode instead of Deny, NSGs allow unrestricted outbound traffic, and NSG flow log retention is under 90 days. Known C2 domains generate alerts but traffic is not blocked, exfiltration flows freely outbound, and flow log evidence ages out before investigation.", fw)

	case "CHAIN-044":
		// Admin credential spray to irrecoverable tenant lock
		return "No phishing-resistant authentication strength is required for admin roles, MFA registration is not enforced, and no emergency access accounts exist. An attacker who sprays admin passwords faces no step-up authentication challenge. Once inside, they can lock out all other admins — and with no break-glass account, recovery requires a Microsoft support case."

	case "CHAIN-045":
		// Event stream hijack
		sb := joinTop(ctx.resourcesByRule["zt_data_019"], 2)
		eh := joinTop(ctx.resourcesByRule["zt_data_018"], 2)
		if sb == "" && eh == "" {
			return ""
		}
		return fmt.Sprintf("Service Bus %s allows public access, Event Hub %s uses Microsoft-managed keys, and no Azure Firewall exists for egress filtering. An attacker who obtains a connection string can read and replay event streams publicly, and the Microsoft-managed encryption means you cannot revoke the key.", sb, eh)

	case "CHAIN-046":
		// Function App compromise to internal pivot
		funcs := joinTop(ctx.resourcesByRule["zt_wl_017"], 3)
		if funcs == "" {
			return ""
		}
		return fmt.Sprintf("Function App(s) %s run outdated runtimes with known CVEs, use stored credentials instead of managed identities, and their subnets have no NSG. An attacker who exploits a runtime vulnerability steals the stored credentials and pivots into the unprotected subnet to reach other workloads.", funcs)

	case "CHAIN-047":
		// NSG flow log evidence destruction
		return "NSG flow logs have retention under 90 days, subnets exist without NSG associations, and storage diagnostic logging is disabled. An attacker operating in an unprotected subnet generates minimal flow data, what little exists is purged before incident response begins, and storage-level access goes entirely unrecorded."

	case "CHAIN-048":
		// Cosmos DB to cross-service data theft
		cosmos := joinTop(ctx.resourcesByRule["zt_data_011"], 3)
		kv := joinTop(ctx.resourcesByRule["zt_data_014"], 3)
		if cosmos == "" {
			return ""
		}
		return fmt.Sprintf("Cosmos DB accounts %s allow traffic from all networks, Key Vault(s) %s have no diagnostic logging and no purge protection. An attacker accesses Cosmos DB over the public endpoint, finds Key Vault connection strings in application config, reads secrets, and purges the vault to destroy evidence.", cosmos, kv)

	case "CHAIN-049":
		// AKS full stack compromise
		acr := joinTop(ctx.resourcesByRule["zt_wl_013"], 2)
		if acr == "" {
			return ""
		}
		return fmt.Sprintf("Container registry %s allows public network access (anchor finding), combined with one or more of: admin account enabled, no network policy, no Azure RBAC, no pod security standards, no Defender for Containers. This creates a multi-path full-stack AKS compromise from registry to node.", acr)

	case "CHAIN-050":
		// Defender notification black hole
		return fmt.Sprintf("In %s, Defender for Cloud email notifications are not configured, no Azure Monitor alert rules exist, and no action groups are set up. Microsoft Defender may detect threats — but no one is ever notified. Alerts accumulate in the portal dashboard unread while the attacker operates freely.", ctx.subscriptionName)

	case "CHAIN-051":
		// Token replay to persistent backdoor
		return "Access token lifetimes exceed the secure 60-minute threshold, no phishing-resistant authentication strength is required for admin roles, and the Activity Log is not exported to Log Analytics. An attacker who steals an admin token has a multi-hour window to establish persistence — creating service principals, adding credentials, modifying policies — with no audit trail reaching a query-able workspace."
	}
	return ""
}

// environmentSummaryFor returns a one-sentence "co-existence" summary
// for a chain that names the affected resources from the customer's
// environment.
func environmentSummaryFor(chainID string, ctx *personalisationContext, fm map[string][]models.Finding) string {
	// Pick the chain's primary trigger rule and name its resources.
	var primary string
	switch chainID {
	case "CHAIN-001", "CHAIN-016":
		primary = "zt_net_001"
	case "CHAIN-002":
		primary = "zt_id_011"
	case "CHAIN-005":
		primary = "zt_data_001"
	case "CHAIN-006", "CHAIN-021":
		primary = "zt_wl_003"
	case "CHAIN-008":
		primary = "zt_vis_003"
	case "CHAIN-019", "CHAIN-004":
		primary = "zt_id_003"
	case "CHAIN-022", "CHAIN-044":
		primary = "zt_id_012"
	case "CHAIN-023":
		primary = "zt_id_023"
	case "CHAIN-024":
		primary = "zt_data_011"
	case "CHAIN-025":
		primary = "zt_wl_014"
	case "CHAIN-026", "CHAIN-049":
		primary = "zt_wl_013"
	case "CHAIN-027":
		primary = "zt_wl_018"
	case "CHAIN-028":
		primary = "zt_data_014"
	case "CHAIN-029":
		primary = "zt_data_012"
	case "CHAIN-030":
		primary = "zt_data_017"
	case "CHAIN-031":
		primary = "zt_net_019"
	case "CHAIN-032":
		primary = "zt_net_014"
	case "CHAIN-033":
		primary = "zt_id_021"
	case "CHAIN-034":
		primary = "zt_id_016"
	case "CHAIN-035":
		primary = "zt_data_020"
	case "CHAIN-036":
		primary = "zt_data_019"
	case "CHAIN-037":
		primary = "zt_net_015"
	case "CHAIN-038":
		primary = "zt_net_017"
	case "CHAIN-039":
		primary = "zt_wl_022"
	case "CHAIN-040":
		primary = "zt_id_018"
	case "CHAIN-041":
		primary = "zt_vis_011"
	case "CHAIN-042":
		primary = "zt_wl_020"
	case "CHAIN-043":
		primary = "zt_net_012"
	case "CHAIN-045":
		primary = "zt_data_019"
	case "CHAIN-046":
		primary = "zt_wl_017"
	case "CHAIN-047":
		primary = "zt_net_019"
	case "CHAIN-048":
		primary = "zt_data_011"
	case "CHAIN-050":
		primary = "zt_vis_020"
	case "CHAIN-051":
		primary = "zt_id_019"
	}
	if primary == "" {
		return ""
	}
	res := ctx.resourcesByRule[primary]
	if len(res) == 0 {
		return ""
	}
	return fmt.Sprintf("In %s, the following resources co-exist with broken controls: %s",
		ctx.subscriptionName, joinTop(res, 5))
}

// joinTop returns a comma-separated list of up to n items from `arr`,
// quoted in single quotes for prose readability. If arr has more than
// n items the suffix " and N more" is appended.
func joinTop(arr []string, n int) string {
	if len(arr) == 0 {
		return ""
	}
	cap := n
	if len(arr) < cap {
		cap = len(arr)
	}
	quoted := make([]string, 0, cap)
	for i := 0; i < cap; i++ {
		quoted = append(quoted, "'"+arr[i]+"'")
	}
	return strings.Join(quoted, ", ")
}

// joinNatural joins a string slice with commas and "and" before the last
// item, the way a human would: "a, b and c".
func joinNatural(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
