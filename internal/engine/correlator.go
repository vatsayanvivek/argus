// Package engine contains the ARGUS attack-chain correlation engine.
//
// The correlator is the CORE differentiator of ARGUS: while every scanner
// on the market produces lists of individual findings, ARGUS stitches
// findings together into realistic, end-to-end attack chains that map
// to how real adversaries (and red teams) actually move through an Azure
// environment. A chain is only emitted when its trigger conditions are met
// by actual findings in the current scan, and every narrative references
// the real resource IDs involved so the report reads like an incident
// write-up rather than a checklist.
package engine

import (
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// ChainPattern is one correlation rule. When its trigger matches the
// finding set, its Builder is invoked to produce a fully populated
// AttackChain using the live snapshot and actual finding instances.
type ChainPattern struct {
	ID           string
	TriggerLogic string // "ALL" | "ANY_TWO" | "ANCHOR_PLUS_ONE"
	TriggerIDs   []string
	AnchorID     string
	Builder      func(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain
}

// Correlator holds the registered chain patterns.
type Correlator struct {
	patterns []ChainPattern
}

// NewCorrelator returns a Correlator populated with every built-in chain
// pattern — both the hand-authored Go builders below (CHAIN-001..051) and
// every data-driven chain spec embedded from internal/engine/chains/*.json.
func NewCorrelator() *Correlator {
	c := &Correlator{}
	defer c.registerDataDrivenChains()
	c.patterns = []ChainPattern{
		{
			ID:           "CHAIN-001",
			TriggerLogic: "ANCHOR_PLUS_ONE",
			AnchorID:     "zt_net_001",
			TriggerIDs:   []string{"zt_net_001", "zt_net_002", "zt_wl_001", "zt_id_001", "zt_id_008"},
			Builder:      buildChain001,
		},
		{
			ID:           "CHAIN-002",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_011", "zt_net_009", "zt_wl_011"},
			Builder:      buildChain002,
		},
		{
			ID:           "CHAIN-003",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_005", "zt_id_006", "zt_id_003"},
			Builder:      buildChain003,
		},
		{
			ID:           "CHAIN-004",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_003", "zt_id_007", "zt_vis_008"},
			Builder:      buildChain004,
		},
		{
			ID:           "CHAIN-005",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_001", "zt_vis_001", "zt_data_006"},
			Builder:      buildChain005,
		},
		{
			ID:           "CHAIN-006",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_003", "zt_wl_007", "zt_data_004"},
			Builder:      buildChain006,
		},
		{
			ID:           "CHAIN-007",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_003", "zt_vis_006", "zt_vis_009"},
			Builder:      buildChain007,
		},
		{
			ID:           "CHAIN-008",
			TriggerLogic: "ANCHOR_PLUS_ONE",
			AnchorID:     "zt_vis_003",
			TriggerIDs:   []string{"zt_vis_003", "zt_net_001", "zt_net_002", "zt_vis_002"},
			Builder:      buildChain008,
		},
		{
			ID:           "CHAIN-009",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_004", "zt_data_005", "zt_vis_004"},
			Builder:      buildChain009,
		},
		{
			ID:           "CHAIN-010",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_010", "zt_data_007", "zt_data_003"},
			Builder:      buildChain010,
		},
		{
			ID:           "CHAIN-011",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_004", "zt_id_006", "zt_vis_005"},
			Builder:      buildChain011,
		},
		{
			ID:           "CHAIN-012",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_004", "zt_wl_010", "zt_vis_001"},
			Builder:      buildChain012,
		},
		{
			ID:           "CHAIN-013",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_004", "zt_net_005", "zt_vis_006"},
			Builder:      buildChain013,
		},
		{
			ID:           "CHAIN-014",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_008", "zt_data_001", "zt_net_009"},
			Builder:      buildChain014,
		},
		{
			ID:           "CHAIN-015",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_005", "zt_wl_008", "zt_data_009"},
			Builder:      buildChain015,
		},
		{
			ID:           "CHAIN-016",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_vis_010", "zt_net_001", "zt_vis_008"},
			Builder:      buildChain016,
		},
		{
			ID:           "CHAIN-017",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_009", "zt_id_010", "zt_vis_004"},
			Builder:      buildChain017,
		},
		{
			ID:           "CHAIN-018",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_008", "zt_net_007", "zt_wl_006"},
			Builder:      buildChain018,
		},
		{
			ID:           "CHAIN-019",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_003", "zt_id_007", "zt_id_010"},
			Builder:      buildChain019,
		},
		{
			ID:           "CHAIN-020",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_vis_007", "zt_vis_001", "zt_vis_005"},
			Builder:      buildChain020,
		},
		{
			ID:           "CHAIN-021",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_002", "zt_wl_003", "zt_wl_007"},
			Builder:      buildChain021,
		},
		{
			ID:           "CHAIN-022",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_012", "zt_id_014", "zt_id_021"},
			Builder:      buildChain022,
		},
		{
			ID:           "CHAIN-023",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_013", "zt_id_018", "zt_id_023"},
			Builder:      buildChain023,
		},
		{
			ID:           "CHAIN-024",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_017", "zt_id_016", "zt_data_011"},
			Builder:      buildChain024,
		},
		{
			ID:           "CHAIN-025",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_014", "zt_wl_015", "zt_wl_016"},
			Builder:      buildChain025,
		},
		{
			ID:           "CHAIN-026",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_012", "zt_wl_013", "zt_wl_021"},
			Builder:      buildChain026,
		},
		{
			ID:           "CHAIN-027",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_018", "zt_net_019", "zt_vis_019"},
			Builder:      buildChain027,
		},
		{
			ID:           "CHAIN-028",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_014", "zt_vis_014", "zt_id_024"},
			Builder:      buildChain028,
		},
		{
			ID:           "CHAIN-029",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_012", "zt_vis_015", "zt_data_015"},
			Builder:      buildChain029,
		},
		{
			ID:           "CHAIN-030",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_013", "zt_data_016", "zt_data_017"},
			Builder:      buildChain030,
		},
		{
			ID:           "CHAIN-031",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_011", "zt_net_019", "zt_net_018"},
			Builder:      buildChain031,
		},
		{
			ID:           "CHAIN-032",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_014", "zt_wl_017", "zt_vis_019"},
			Builder:      buildChain032,
		},
		{
			ID:           "CHAIN-033",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_021", "zt_vis_017", "zt_id_019"},
			Builder:      buildChain033,
		},
		{
			ID:           "CHAIN-034",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_016", "zt_id_017", "zt_id_013"},
			Builder:      buildChain034,
		},
		{
			ID:           "CHAIN-035",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_020", "zt_net_011", "zt_vis_011"},
			Builder:      buildChain035,
		},
		{
			ID:           "CHAIN-036",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_019", "zt_data_018", "zt_vis_016"},
			Builder:      buildChain036,
		},
		{
			ID:           "CHAIN-037",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_015", "zt_net_016", "zt_net_020"},
			Builder:      buildChain037,
		},
		{
			ID:           "CHAIN-038",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_017", "zt_net_013", "zt_wl_019"},
			Builder:      buildChain038,
		},
		{
			ID:           "CHAIN-039",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_022", "zt_wl_014", "zt_data_014"},
			Builder:      buildChain039,
		},
		{
			ID:           "CHAIN-040",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_018", "zt_id_022", "zt_id_015"},
			Builder:      buildChain040,
		},
		{
			ID:           "CHAIN-041",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_vis_011", "zt_vis_017", "zt_vis_018"},
			Builder:      buildChain041,
		},
		{
			ID:           "CHAIN-042",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_020", "zt_data_017", "zt_vis_012"},
			Builder:      buildChain042,
		},
		{
			ID:           "CHAIN-043",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_net_012", "zt_net_018", "zt_vis_013"},
			Builder:      buildChain043,
		},
		{
			ID:           "CHAIN-044",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_014", "zt_id_023", "zt_id_012"},
			Builder:      buildChain044,
		},
		{
			ID:           "CHAIN-045",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_018", "zt_data_019", "zt_net_011"},
			Builder:      buildChain045,
		},
		{
			ID:           "CHAIN-046",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_wl_017", "zt_id_025", "zt_net_019"},
			Builder:      buildChain046,
		},
		{
			ID:           "CHAIN-047",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_vis_013", "zt_net_019", "zt_vis_016"},
			Builder:      buildChain047,
		},
		{
			ID:           "CHAIN-048",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_data_011", "zt_vis_014", "zt_data_014"},
			Builder:      buildChain048,
		},
		{
			ID:           "CHAIN-049",
			TriggerLogic: "ANCHOR_PLUS_ONE",
			AnchorID:     "zt_wl_013",
			TriggerIDs:   []string{"zt_wl_013", "zt_wl_012", "zt_wl_014", "zt_wl_015", "zt_wl_016", "zt_wl_021"},
			Builder:      buildChain049,
		},
		{
			ID:           "CHAIN-050",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_vis_020", "zt_vis_012", "zt_vis_018"},
			Builder:      buildChain050,
		},
		{
			ID:           "CHAIN-051",
			TriggerLogic: "ALL",
			TriggerIDs:   []string{"zt_id_019", "zt_id_014", "zt_vis_017"},
			Builder:      buildChain051,
		},
	}
	return c
}

// Correlate evaluates every registered pattern against the given finding
// set and returns the chains that triggered, sorted CRITICAL-first and
// then by chain ID.
func (c *Correlator) Correlate(findings []models.Finding, snapshot *models.AzureSnapshot) []models.AttackChain {
	findingMap := make(map[string][]models.Finding)
	for _, f := range findings {
		findingMap[f.ID] = append(findingMap[f.ID], f)
	}

	// Build a customisation context once per scan. The personaliser
	// uses this to inject real resource names, user counts, tenant
	// IDs, and other environment-specific facts into chain narratives.
	pctx := buildPersonalisationContext(snapshot, findingMap)

	out := []models.AttackChain{}
	for _, p := range c.patterns {
		if !p.triggerMatches(findingMap) {
			continue
		}
		chain := p.Builder(findingMap, snapshot)
		if chain == nil {
			continue
		}
		// Re-write the narrative with concrete details from the
		// customer's environment so the chain reads like a consultant
		// wrote it for them, not a generic template.
		personaliseChain(chain, pctx, findingMap)
		out = append(out, *chain)
	}

	sort.SliceStable(out, func(i, j int) bool {
		si := severityRank(out[i].Severity)
		sj := severityRank(out[j].Severity)
		if si != sj {
			return si < sj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ExampleChains runs every registered pattern's Builder against an empty
// finding set and returns the resulting *AttackChain slice. Useful for
// documentation generation and for `argus explain` — the narratives,
// steps, and blast-radius fields are static strings that do not depend
// on scan findings, so an empty input reveals the full templated form
// of every chain. Builders that defensively bail on empty input are
// skipped.
func (c *Correlator) ExampleChains() []models.AttackChain {
	empty := map[string][]models.Finding{}
	snap := &models.AzureSnapshot{}
	out := make([]models.AttackChain, 0, len(c.patterns))
	for _, p := range c.patterns {
		// Builders expect their trigger rule ids to be present; inject
		// a placeholder finding per trigger so the builder's
		// extractResourceIDs / collectFindingIDs calls see matching keys.
		primed := map[string][]models.Finding{}
		for _, rid := range p.TriggerIDs {
			primed[rid] = []models.Finding{{ID: rid, ResourceID: "<example>"}}
		}
		ch := p.Builder(primed, snap)
		_ = empty
		if ch == nil {
			continue
		}
		out = append(out, *ch)
	}
	return out
}

// MarkChainParticipants flags findings that participate in any emitted
// chain. ChainPriority is set for findings that appear in a chain's
// TriggerFindings so the report can surface them first.
func (c *Correlator) MarkChainParticipants(findings []models.Finding, chains []models.AttackChain) {
	index := make(map[string][]string)
	for _, ch := range chains {
		for _, ruleID := range ch.TriggerFindings {
			index[ruleID] = append(index[ruleID], ch.ID)
		}
	}
	for i := range findings {
		if ids, ok := index[findings[i].ID]; ok {
			findings[i].ParticipatesInChains = append(findings[i].ParticipatesInChains, ids...)
			findings[i].ChainPriority = true
		}
	}
}

// triggerMatches evaluates the pattern's trigger logic against the map.
func (p *ChainPattern) triggerMatches(findings map[string][]models.Finding) bool {
	switch p.TriggerLogic {
	case "ALL":
		for _, id := range p.TriggerIDs {
			if len(findings[id]) == 0 {
				return false
			}
		}
		return true
	case "ANY_TWO":
		hit := 0
		for _, id := range p.TriggerIDs {
			if len(findings[id]) > 0 {
				hit++
			}
			if hit >= 2 {
				return true
			}
		}
		return false
	case "ANCHOR_PLUS_ONE":
		if len(findings[p.AnchorID]) == 0 {
			return false
		}
		for _, id := range p.TriggerIDs {
			if id == p.AnchorID {
				continue
			}
			if len(findings[id]) > 0 {
				return true
			}
		}
		return false
	}
	return false
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

// extractResourceIDs returns the de-duplicated list of ResourceIDs across
// the supplied rule IDs, preserving first-seen order.
func extractResourceIDs(findings map[string][]models.Finding, ruleIDs ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, rid := range ruleIDs {
		for _, f := range findings[rid] {
			if !seen[f.ResourceID] {
				seen[f.ResourceID] = true
				out = append(out, f.ResourceID)
			}
		}
	}
	return out
}

// collectFindingIDs returns the subset of rule IDs that actually have a
// finding in the supplied map, in the order given.
func collectFindingIDs(findings map[string][]models.Finding, ruleIDs ...string) []string {
	out := []string{}
	for _, rid := range ruleIDs {
		if _, ok := findings[rid]; ok {
			out = append(out, rid)
		}
	}
	return out
}

// envSummary produces the stock "In your subscription..." line referencing
// the real resource IDs that triggered the chain.
func envSummary(resources []string) string {
	if len(resources) == 0 {
		return "In your subscription, these conditions co-exist across multiple resources."
	}
	return "In your subscription, these conditions co-exist on resources: " + strings.Join(resources, ", ")
}

// ---------------------------------------------------------------------------
// CHAIN-001: Internet-exposed VM to subscription takeover
// ---------------------------------------------------------------------------

func buildChain001(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_001", "zt_net_002", "zt_wl_001", "zt_id_001", "zt_id_008")
	triggers := collectFindingIDs(findings, "zt_net_001", "zt_net_002", "zt_wl_001", "zt_id_001", "zt_id_008")

	return &models.AttackChain{
		ID:                 "CHAIN-001",
		Title:              "Internet-exposed VM to subscription takeover",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An attacker scans Azure IP space, finds a VM with RDP or SSH open to 0.0.0.0/0, and walks into a login prompt. " +
			"Because the VM runs with a System-Assigned Managed Identity that has been granted a privileged role at subscription scope, " +
			"any code execution on that box yields a subscription-level Azure AD token through IMDS. " +
			"From there the attacker uses the token to enumerate and impersonate other principals, create new credentials, " +
			"and ultimately owns every resource in the subscription without ever touching a stolen password. " +
			"This is the single most common 'one click to game over' pattern red teams exploit in Azure.",
		TriggerFindings: triggers,
		TriggerLogic:    "ANCHOR_PLUS_ONE",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Scan Azure public IP ranges for VMs exposing RDP/3389 or SSH/22 to the internet.",
				Technical: "Shodan / masscan against published Azure prefixes; NSG rule with SourceAddressPrefix='*' and DestinationPortRange='22' or '3389' is directly discoverable.",
				Technique: "T1595.001",
				EnabledBy: "zt_net_001",
				Gain:      "Candidate list of reachable VMs; zero authentication required to reach the management port.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Brute-force or password-spray the exposed management port against local admin accounts.",
				Technical: "Hydra/crowbar against RDP/SSH; local accounts have no tenant-level lockout, no Conditional Access, and no MFA.",
				Technique: "T1110.003",
				EnabledBy: "zt_net_002",
				Gain:      "Interactive shell on the VM as a local administrator.",
			},
			{
				Number:    3,
				Actor:     "Attacker on VM",
				Action:    "Query the Instance Metadata Service (IMDS) to retrieve the VM's managed identity access token.",
				Technical: "curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true",
				Technique: "T1552.005",
				EnabledBy: "zt_wl_001",
				Gain:      "A valid ARM bearer token tied to the VM's System-Assigned identity.",
			},
			{
				Number:    4,
				Actor:     "Attacker with MI token",
				Action:    "Enumerate the identity's role assignments and discover it holds Contributor or Owner at subscription scope.",
				Technical: "GET /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?$filter=principalId eq '{miId}'",
				Technique: "T1087.004",
				EnabledBy: "zt_id_001",
				Gain:      "Confirmation that the stolen token controls the entire subscription, not just the host VM.",
			},
			{
				Number:    5,
				Actor:     "Attacker with subscription rights",
				Action:    "Create a new service principal with Owner rights and a long-lived client secret for durable access.",
				Technical: "New-AzADServicePrincipal followed by New-AzRoleAssignment -RoleDefinitionName Owner -Scope /subscriptions/{sub}",
				Technique: "T1136.003",
				EnabledBy: "zt_id_008",
				Gain:      "Persistent Owner-level credential that survives VM decommission and IR containment.",
			},
			{
				Number:    6,
				Actor:     "Attacker with persistence",
				Action:    "Export Key Vault secrets, Storage keys, and SQL admin passwords subscription-wide.",
				Technical: "az keyvault secret list/show across every vault; storage account keys listed via listKeys; SQL admin rotation via resource manager.",
				Technique: "T1555.006",
				EnabledBy: "zt_id_001",
				Gain:      "Full subscription compromise: every data store, every credential, every workload.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Single internet-exposed VM with management ports open to 0.0.0.0/0.",
			LateralMovement:    "IMDS token → ARM control plane → every resource in the subscription via managed identity RBAC.",
			MaxPrivilege:       "Subscription Owner via System-Assigned Managed Identity inherited by the compromised VM.",
			DataAtRisk:         []string{"Key Vault secrets", "Storage account contents", "SQL databases", "Cosmos DB accounts", "Disk snapshots"},
			ServicesAtRisk:     []string{"Compute", "Storage", "Key Vault", "SQL", "Resource Manager", "Entra ID service principals"},
			EstimatedScopePerc: "100% of the subscription",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "1.3.1 / 1.4.1", Impact: "Inbound traffic from untrusted networks to the cardholder data environment is not restricted; direct internet exposure of management ports is an automatic finding."},
			{Framework: "ISO 27001:2022", Control: "A.9.4.1 / A.13.1.3", Impact: "Network access control to privileged services is not enforced; segregation between trusted and untrusted networks fails."},
			{Framework: "SOC 2", Control: "CC6.1 / CC6.6", Impact: "Logical access controls over infrastructure fail: the entity did not restrict physical and logical access to system resources."},
		},
		MinimalFixSet: []string{"zt_net_001", "zt_wl_001"},
		PriorityFix: "Close the NSG rule first - removing 0.0.0.0/0 on RDP/SSH breaks the chain instantly even if the managed identity stays over-privileged. " +
			"Then right-size the VM's managed identity to least-privilege scope (resource group or resource, not subscription).",
		BreakingNote: "Closing the NSG will break any jump-box workflow that depends on direct RDP/SSH from the internet. " +
			"Route administrators through Azure Bastion or a site-to-site VPN before applying the change in production.",
		MITRETechnique:    "T1190 / T1078.004",
		MITRETactic:       "Initial Access / Privilege Escalation",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-002: App Registration Graph abuse to tenant data
// ---------------------------------------------------------------------------

func buildChain002(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_011", "zt_net_009", "zt_wl_011")
	triggers := collectFindingIDs(findings, "zt_id_011", "zt_net_009", "zt_wl_011")

	return &models.AttackChain{
		ID:                 "CHAIN-002",
		Title:              "App Registration Graph abuse to tenant data",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "This is the scenario only red teams catch. An App Registration in the tenant holds high-privilege application-level Microsoft Graph permissions " +
			"(Mail.Read.All, Files.Read.All, User.Read.All or worse - Directory.ReadWrite.All). " +
			"Its client secret is stored in an internet-reachable location: a public storage blob, a committed .env file, or a workload whose outbound egress is unrestricted. " +
			"An attacker who gets that secret can authenticate to Graph as the application - bypassing every user-centric control the tenant has - and read mailboxes, files, " +
			"and directory objects tenant-wide. There is no user, no device, no MFA prompt, no Conditional Access policy in the path because application tokens do not honor them. " +
			"Scanners that look at findings in isolation never connect the secret leak to the Graph permission grant; ARGUS does.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Enumerate public tenant App Registrations and identify one holding application-level Graph permissions with standing consent.",
				Technical: "Probe /common/discovery/instance, scrape GitHub for committed appId+tenantId pairs, cross-reference with leaked secrets dumps.",
				Technique: "T1589.001",
				EnabledBy: "zt_id_011",
				Gain:      "Knowledge that a single secret unlocks tenant-wide Graph read access.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Harvest the App Registration client secret from an egress-unrestricted workload or exposed storage.",
				Technical: "Unrestricted outbound NSG allows the compromised workload to exfil its environment variables to attacker-controlled infrastructure; alternatively a public blob hosts the .env.",
				Technique: "T1552.001",
				EnabledBy: "zt_net_009",
				Gain:      "Valid clientId + clientSecret for the App Registration.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Exchange the client credentials for an application Graph token.",
				Technical: "POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token with grant_type=client_credentials, scope=https://graph.microsoft.com/.default",
				Technique: "T1550.001",
				EnabledBy: "zt_wl_011",
				Gain:      "A bearer token authenticated as the application - no user context, no Conditional Access, no MFA.",
			},
			{
				Number:    4,
				Actor:     "Attacker with app token",
				Action:    "Read tenant-wide mailboxes, OneDrive/SharePoint files, and directory objects via Graph.",
				Technical: "GET https://graph.microsoft.com/v1.0/users/{id}/messages, /drives/{id}/root/children, /users with $select=* - all succeed against every user in the tenant.",
				Technique: "T1530",
				EnabledBy: "zt_id_011",
				Gain:      "Bulk exfiltration of executive email, M&A documents, HR files, and the full user directory.",
			},
			{
				Number:    5,
				Actor:     "Attacker with app token",
				Action:    "Add a new password credential to the App Registration for durable, rotation-proof access.",
				Technical: "POST https://graph.microsoft.com/v1.0/applications/{id}/addPassword - application tokens with Application.ReadWrite.OwnedBy (or higher) can self-rotate credentials.",
				Technique: "T1098.001",
				EnabledBy: "zt_wl_011",
				Gain:      "Independent, attacker-controlled secret on the App Registration. Even rotating the original secret does not evict the attacker.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Leaked App Registration client secret obtained via egress-unrestricted workload or exposed storage.",
			LateralMovement:    "Direct to Microsoft Graph with application token - no lateral movement required; the single token is the keys to the tenant.",
			MaxPrivilege:       "Tenant-wide application-level Graph access (Mail/Files/Directory). Not scoped to a subscription - scoped to the entire Entra ID tenant.",
			DataAtRisk:         []string{"All user mailboxes", "All OneDrive/SharePoint content", "Entra ID directory objects", "Group memberships", "Calendar and Teams chats"},
			ServicesAtRisk:     []string{"Exchange Online", "SharePoint Online", "OneDrive", "Entra ID", "Microsoft Teams"},
			EstimatedScopePerc: "100% of the Entra ID tenant",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "GDPR", Control: "Article 32", Impact: "Failure to implement appropriate technical measures to ensure confidentiality: a single leaked secret grants tenant-wide access to personal data."},
			{Framework: "PCI DSS 4.0", Control: "3.4 / 8.3", Impact: "Stored authentication secrets (application credentials) are not protected; strong authentication for access to cardholder-adjacent systems is bypassed because application tokens ignore MFA."},
			{Framework: "ISO 27001:2022", Control: "A.9.4.1 / A.9.2.3", Impact: "Privileged access rights for non-human identities are not controlled or reviewed; application permissions act as standing privilege."},
		},
		MinimalFixSet: []string{"zt_id_011", "zt_net_009"},
		PriorityFix:   "Remove high-privilege application-level Graph permissions from App Registration immediately.",
		BreakingNote: "If the App Registration legitimately needs Graph access, replace Application permissions with Delegated permissions and move to a Managed Identity scoped to the exact data objects required. " +
			"Expect to refactor any daemon that currently uses client_credentials flow.",
		MITRETechnique:    "T1550 / T1530",
		MITRETactic:       "Lateral Movement / Collection",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-003: Legacy auth bypass to privileged takeover
// ---------------------------------------------------------------------------

func buildChain003(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_005", "zt_id_006", "zt_id_003")
	triggers := collectFindingIDs(findings, "zt_id_005", "zt_id_006", "zt_id_003")

	return &models.AttackChain{
		ID:                 "CHAIN-003",
		Title:              "Legacy auth bypass to privileged takeover",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Legacy authentication protocols (POP, IMAP, SMTP AUTH, Exchange ActiveSync basic auth) are still enabled at the tenant level, and no Conditional Access policy blocks them. " +
			"Attackers password-spray these endpoints because they bypass MFA entirely - the protocol pre-dates modern auth. " +
			"One of the accounts that falls has a permanently-assigned Global Administrator or Privileged Role Administrator role (no PIM, no just-in-time elevation), " +
			"so a single successful spray yields full tenant control without ever triggering an MFA prompt.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Password-spray the Exchange Online legacy auth endpoint with a common-password list against scraped usernames.",
				Technical: "MSOLSpray / o365spray against https://outlook.office365.com/EWS/Exchange.asmx using Basic auth; legacy protocols accept credentials without MFA.",
				Technique: "T1110.003",
				EnabledBy: "zt_id_005",
				Gain:      "One or more valid user credentials with no MFA challenge.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Log in to Azure Portal with the stolen credential; no Conditional Access blocks the session.",
				Technical: "No CA policy requiring MFA on 'All cloud apps' + 'All users'; sign-in risk evaluation is not configured as a grant control.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_006",
				Gain:      "Interactive tenant session as the compromised user.",
			},
			{
				Number:    3,
				Actor:     "Attacker as user",
				Action:    "Discover the account holds a permanently-assigned privileged directory role.",
				Technical: "Get-AzureADDirectoryRoleMember / Get-MgRoleManagementDirectoryRoleAssignment returns Global Administrator active at role scope /.",
				Technique: "T1087.004",
				EnabledBy: "zt_id_003",
				Gain:      "Confirmation that the stolen account is Global Admin 24/7, not eligible-via-PIM.",
			},
			{
				Number:    4,
				Actor:     "Attacker as Global Admin",
				Action:    "Create a backdoor account and a new Conditional Access exclusion covering it.",
				Technical: "New-MgUser + New-MgRoleManagementDirectoryRoleAssignment + update CA policies to exclude the new identity.",
				Technique: "T1136.003",
				EnabledBy: "zt_id_003",
				Gain:      "Persistent Global Administrator foothold that survives password resets on the original victim.",
			},
			{
				Number:    5,
				Actor:     "Attacker as Global Admin",
				Action:    "Reset MFA and passwords on other privileged users, export audit logs, and disable security alerts.",
				Technical: "Reset-MgUserAuthenticationMethod + Remove-MgAuditLogDirectoryAudit; Defender for Cloud alert rules can be silenced by a Global Admin.",
				Technique: "T1562.001",
				EnabledBy: "zt_id_003",
				Gain:      "Full tenant compromise with reduced detection surface.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Legacy authentication endpoint (Exchange Basic, POP, IMAP, SMTP AUTH) reachable from the internet.",
			LateralMovement:    "User sign-in to portal.azure.com → permanently-active privileged role → tenant-wide control plane.",
			MaxPrivilege:       "Global Administrator at tenant scope.",
			DataAtRisk:         []string{"Entra ID directory", "Exchange mailboxes", "Conditional Access policies", "Audit logs", "All Azure subscriptions in the tenant"},
			ServicesAtRisk:     []string{"Entra ID", "Exchange Online", "Azure Resource Manager", "Microsoft 365"},
			EstimatedScopePerc: "100% of the tenant",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "IA-2(1) / IA-2(2)", Impact: "Multi-factor authentication for privileged and non-privileged accounts is not enforced on network access paths."},
			{Framework: "ISO 27001:2022", Control: "A.9.4.2", Impact: "Secure log-on procedures are not in place: legacy protocols weaken the authentication process."},
			{Framework: "SOC 2", Control: "CC6.1", Impact: "Logical access security fails because legacy auth does not require second-factor verification."},
		},
		MinimalFixSet: []string{"zt_id_005", "zt_id_003"},
		PriorityFix: "Disable legacy authentication tenant-wide via Set-MsolCompanySettings -DisableLegacyAuth $true and a CA policy blocking 'Other clients'. " +
			"Then convert all permanent privileged role assignments to PIM-eligible.",
		BreakingNote: "Disabling legacy auth can break older Outlook clients (pre-2016), MFP scan-to-email devices, and line-of-business apps that use Basic auth. " +
			"Inventory usage in sign-in logs before cutover.",
		MITRETechnique:    "T1110 / T1078.004",
		MITRETactic:       "Credential Access / Privilege Escalation",
		KillChainPhase:    "Initial Access",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-004: Permanent privilege no PIM to insider escalation
// ---------------------------------------------------------------------------

func buildChain004(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_003", "zt_id_007", "zt_vis_008")
	triggers := collectFindingIDs(findings, "zt_id_003", "zt_id_007", "zt_vis_008")

	return &models.AttackChain{
		ID:                 "CHAIN-004",
		Title:              "Permanent privilege no PIM to insider escalation",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Privileged roles are permanently assigned instead of PIM-eligible, the tenant has no automated access reviews, and there is no alerting on role membership changes. " +
			"A disgruntled insider - or an attacker who pivoted into a helpdesk account - can quietly add themselves to a Global Admin or Owner role and retain that privilege indefinitely " +
			"because nothing ever reconciles the assignment list against a business owner.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Malicious insider",
				Action:    "Enumerate existing permanently-assigned privileged roles to identify low-noise elevation targets.",
				Technical: "Get-MgRoleManagementDirectoryRoleAssignment reveals all Active assignments including User Access Administrator at subscription scope.",
				Technique: "T1087.004",
				EnabledBy: "zt_id_003",
				Gain:      "Knowledge of which privileged accounts exist and where the gaps are.",
			},
			{
				Number:    2,
				Actor:     "Malicious insider",
				Action:    "Add a new permanent role assignment to self or a controlled account.",
				Technical: "New-MgRoleManagementDirectoryRoleAssignment -PrincipalId {self} -RoleDefinitionId {GlobalAdmin}; no PIM approval workflow blocks this.",
				Technique: "T1098.003",
				EnabledBy: "zt_id_007",
				Gain:      "Direct, permanent Global Administrator rights without eligibility review or approval.",
			},
			{
				Number:    3,
				Actor:     "Malicious insider",
				Action:    "Wait out the quarter - no access review ever fires to catch the assignment.",
				Technical: "Access Reviews are not configured for directory roles; no periodic recertification exists.",
				Technique: "T1078.004",
				EnabledBy: "zt_vis_008",
				Gain:      "Indefinite persistence. The assignment blends into the baseline because the baseline is never audited.",
			},
			{
				Number:    4,
				Actor:     "Malicious insider",
				Action:    "Use the standing privilege to exfiltrate data or sabotage systems at a time of their choosing.",
				Technical: "Subscription-wide resource export, mailbox impersonation via application access policy, or destructive operations with no alerting in place.",
				Technique: "T1530",
				EnabledBy: "zt_id_003",
				Gain:      "Complete freedom of action across the tenant with attribution obscured by the absence of reviews.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Existing insider account (employee, contractor, or compromised helpdesk).",
			LateralMovement:    "Self-elevation via direct role assignment; no approval gate, no time bounding.",
			MaxPrivilege:       "Global Administrator / subscription Owner, permanent.",
			DataAtRisk:         []string{"Tenant directory", "All Azure subscriptions", "Exchange and SharePoint data"},
			ServicesAtRisk:     []string{"Entra ID", "All Azure resources", "Microsoft 365 workloads"},
			EstimatedScopePerc: "100% of the tenant over time",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "SOC 2", Control: "CC6.2 / CC6.3", Impact: "User access is not reviewed on a timely basis; separation of duties fails because a single actor can both assign and hold privilege."},
			{Framework: "ISO 27001:2022", Control: "A.9.2.5 / A.9.2.6", Impact: "Review of user access rights and removal of access are not performed; privileged assignments are not time-bound."},
			{Framework: "NIST 800-53", Control: "AC-2(7) / AC-6(7)", Impact: "Privileged account management and least privilege reviews are absent."},
		},
		MinimalFixSet: []string{"zt_id_007", "zt_vis_008"},
		PriorityFix: "Move every permanent privileged role assignment to PIM-eligible with approval workflow and MFA on activation. " +
			"Configure quarterly access reviews on all directory roles.",
		BreakingNote: "Operational teams that currently rely on standing admin for incident response will need to activate their role via PIM. " +
			"Ensure break-glass accounts remain permanently assigned and are excluded from reviews.",
		MITRETechnique:    "T1098.003 / T1078.004",
		MITRETactic:       "Persistence / Privilege Escalation",
		KillChainPhase:    "Privilege Escalation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-005: Public storage no diagnostics to silent exfil
// ---------------------------------------------------------------------------

func buildChain005(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_001", "zt_vis_001", "zt_data_006")
	triggers := collectFindingIDs(findings, "zt_data_001", "zt_vis_001", "zt_data_006")

	return &models.AttackChain{
		ID:                 "CHAIN-005",
		Title:              "Public storage no diagnostics to silent exfil",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "A storage account allows public blob access, has no diagnostic settings streaming to Log Analytics, and encryption is either using platform-managed keys or disabled at the container level. " +
			"An attacker who guesses or enumerates the container name can list and download every blob, and because StorageRead logs never left the resource, " +
			"there is no evidence an exfiltration occurred. The breach is only noticed when the data shows up in a dump.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Enumerate Azure storage account names via DNS brute-force against *.blob.core.windows.net.",
				Technical: "DNS resolution of candidate names reveals live accounts; anonymous GET against common container paths (backups, data, public, assets) completes the discovery.",
				Technique: "T1580",
				EnabledBy: "zt_data_001",
				Gain:      "Confirmed reachable, anonymously-readable containers.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "List and download all blobs using the unauthenticated REST endpoint.",
				Technical: "GET https://{account}.blob.core.windows.net/{container}?restype=container&comp=list - returns full blob inventory; follow with GET per blob.",
				Technique: "T1530",
				EnabledBy: "zt_data_001",
				Gain:      "Bulk copy of every blob in the container - backups, PII, source code, secrets.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Operate without detection because diagnostic logs are not forwarded.",
				Technical: "No diagnosticSettings resource attached to the storage account; StorageRead/StorageWrite logs never leave the account and are purged after the retention window.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_001",
				Gain:      "Zero telemetry of the attack. Defenders have no events to correlate.",
			},
			{
				Number:    4,
				Actor:     "External attacker",
				Action:    "Decrypt any blobs that used weak or platform-default encryption where the key was accessible.",
				Technical: "Blobs encrypted with Microsoft-managed keys are transparently decrypted on read; customer-managed keys were not enforced so the attacker receives plaintext.",
				Technique: "T1486",
				EnabledBy: "zt_data_006",
				Gain:      "Plaintext access to sensitive data without needing to compromise Key Vault.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Anonymous internet access to public storage containers.",
			LateralMovement:    "None required - the data is directly reachable.",
			MaxPrivilege:       "Read (and potentially write) on every blob in exposed containers.",
			DataAtRisk:         []string{"Backups", "Application data", "Customer PII", "Source code", "Embedded secrets and tokens"},
			ServicesAtRisk:     []string{"Azure Storage", "Any downstream system whose secrets were in exfiltrated blobs"},
			EstimatedScopePerc: "All publicly-exposed containers on affected storage accounts",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "GDPR", Control: "Article 32 / Article 33", Impact: "Personal data was not protected against unauthorised disclosure; absence of diagnostic logs means the 72-hour breach notification clock may have started long before discovery."},
			{Framework: "PCI DSS 4.0", Control: "3.5 / 10.2", Impact: "Stored account data is not protected; audit trails to detect and reconstruct access events are missing."},
			{Framework: "HIPAA", Control: "164.312(b)", Impact: "Audit controls requirement fails: no mechanism to record and examine activity in systems containing ePHI."},
		},
		MinimalFixSet: []string{"zt_data_001", "zt_vis_001"},
		PriorityFix: "Set AllowBlobPublicAccess=false on the storage account immediately. Enabling diagnostic settings afterwards gives retroactive visibility on any lingering access.",
		BreakingNote: "If legitimate applications rely on anonymous access (e.g., static website assets), migrate them to a CDN with origin authentication or to an Azure Front Door with managed identity before flipping the flag.",
		MITRETechnique:    "T1530 / T1562.008",
		MITRETactic:       "Collection / Defense Evasion",
		KillChainPhase:    "Exfiltration",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-006: AKS public endpoint privileged containers to takeover
// ---------------------------------------------------------------------------

func buildChain006(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_003", "zt_wl_007", "zt_data_004")
	triggers := collectFindingIDs(findings, "zt_wl_003", "zt_wl_007", "zt_data_004")

	return &models.AttackChain{
		ID:                 "CHAIN-006",
		Title:              "AKS public endpoint privileged containers to takeover",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An AKS cluster has its API server reachable over the internet, pods are permitted to run as privileged or with hostPath mounts, " +
			"and the cluster's managed identity can fetch secrets from a Key Vault whose soft-delete/purge protection is disabled. " +
			"An attacker who hijacks the kubeconfig (or exploits an unauthenticated API server endpoint) escapes a container, accesses the node filesystem, " +
			"pulls the cluster identity token, and drains the Key Vault - then purges the vault to destroy forensic evidence.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Reach the AKS API server from the internet and exploit weak authentication or a known CVE.",
				Technical: "Public FQDN *.hcp.{region}.azmk8s.io reachable from anywhere; combined with aged kubeconfig or misconfigured OIDC, the attacker obtains cluster-admin.",
				Technique: "T1190",
				EnabledBy: "zt_wl_003",
				Gain:      "kubectl access to the cluster.",
			},
			{
				Number:    2,
				Actor:     "Attacker with kubectl",
				Action:    "Deploy a privileged pod with hostPath=/ and run as root to break out to the node.",
				Technical: "kubectl apply of a pod spec with securityContext.privileged=true and volumes[].hostPath.path=/ - PodSecurity admission is set to baseline/privileged.",
				Technique: "T1611",
				EnabledBy: "zt_wl_007",
				Gain:      "Root shell on the underlying AKS node.",
			},
			{
				Number:    3,
				Actor:     "Attacker on node",
				Action:    "Query IMDS from the node and obtain the kubelet's managed identity token.",
				Technical: "curl http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net - node identity has Key Vault Reader or Secrets User.",
				Technique: "T1552.005",
				EnabledBy: "zt_wl_007",
				Gain:      "Bearer token for Azure Key Vault scoped to the cluster identity.",
			},
			{
				Number:    4,
				Actor:     "Attacker with KV token",
				Action:    "Exfiltrate every secret from the associated Key Vault.",
				Technical: "az keyvault secret list + per-secret show using the managed identity token; database credentials, API keys, signing certs all disclosed.",
				Technique: "T1555.006",
				EnabledBy: "zt_data_004",
				Gain:      "Downstream credential reuse across SQL, service principals, and partner APIs.",
			},
			{
				Number:    5,
				Actor:     "Attacker with KV admin",
				Action:    "Purge the Key Vault to destroy forensic evidence.",
				Technical: "Because soft-delete / purge protection is disabled, az keyvault delete followed by az keyvault purge succeeds. Secret version history is unrecoverable.",
				Technique: "T1485",
				EnabledBy: "zt_data_004",
				Gain:      "Destruction of audit trail and rotation baseline, impeding recovery.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Public AKS API server.",
			LateralMovement:    "Container → privileged pod → node → Azure IMDS → Key Vault.",
			MaxPrivilege:       "cluster-admin on AKS + Key Vault secret reader/purger on the associated vault.",
			DataAtRisk:         []string{"Cluster workloads", "Node filesystems", "All Key Vault secrets", "Downstream services whose credentials were in the vault"},
			ServicesAtRisk:     []string{"AKS", "Key Vault", "Any service whose credentials were in the vault"},
			EstimatedScopePerc: "Cluster + associated vault + every downstream service whose creds were in the vault",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "1.2 / 2.2", Impact: "Network security controls and secure configurations are not applied to the AKS API server or pod runtime."},
			{Framework: "NIST 800-53", Control: "SC-7 / AC-6", Impact: "Boundary protection and least privilege are not enforced on the container platform."},
			{Framework: "ISO 27001:2022", Control: "A.8.9 / A.8.16", Impact: "Configuration management and monitoring of privileged operations fail on the cluster."},
		},
		MinimalFixSet: []string{"zt_wl_003", "zt_wl_007"},
		PriorityFix: "Convert the AKS cluster to a private cluster (API server VNet integration) and enforce PodSecurity 'restricted' admission to block privileged containers.",
		BreakingNote: "Migrating to a private cluster requires bastion/jumpbox access for kubectl operators and may break CI/CD runners that deploy from public networks. " +
			"Enforcing restricted pod security will reject any existing workload that relies on hostPath or privileged mode.",
		MITRETechnique:    "T1190 / T1611",
		MITRETactic:       "Initial Access / Privilege Escalation",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-007: No NSG on subnet no flow logs to invisible lateral
// ---------------------------------------------------------------------------

func buildChain007(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_003", "zt_vis_006", "zt_vis_009")
	triggers := collectFindingIDs(findings, "zt_net_003", "zt_vis_006", "zt_vis_009")

	return &models.AttackChain{
		ID:                 "CHAIN-007",
		Title:              "No NSG on subnet no flow logs to invisible lateral",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "A subnet has no NSG attached, NSG flow logs are not configured anywhere in the VNet, and Traffic Analytics is not enabled. " +
			"An attacker who lands on any resource in that subnet can move laterally to every other resource in the same broadcast domain without any layer-4 filtering or any telemetry. " +
			"Defenders see nothing because there is literally no log source.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker on foothold VM",
				Action:    "Perform internal port scanning across the subnet CIDR.",
				Technical: "nmap -sS against the subnet's CIDR block; no NSG denies the traffic and no flow log captures it.",
				Technique: "T1046",
				EnabledBy: "zt_net_003",
				Gain:      "Full inventory of live hosts and open services on the subnet.",
			},
			{
				Number:    2,
				Actor:     "Attacker on foothold VM",
				Action:    "Move laterally to a database or file server in the same subnet.",
				Technical: "Direct TCP connect to SQL/1433, SMB/445, WinRM/5985 on neighboring hosts - all allowed by the absent NSG.",
				Technique: "T1021.002",
				EnabledBy: "zt_net_003",
				Gain:      "Expanded foothold to stateful services holding business data.",
			},
			{
				Number:    3,
				Actor:     "Attacker on second host",
				Action:    "Operate without any flow-level observation.",
				Technical: "NSG Flow Logs v2 are not enabled; no records arrive in storage or Log Analytics.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_006",
				Gain:      "Lateral movement leaves no east-west network audit trail.",
			},
			{
				Number:    4,
				Actor:     "Attacker on second host",
				Action:    "Evade behavioural detection because Traffic Analytics is not on.",
				Technical: "Traffic Analytics workspace not bound to the network watcher; no behavioural baselines exist to flag anomalous flows.",
				Technique: "T1562.001",
				EnabledBy: "zt_vis_009",
				Gain:      "Sustained unobserved dwell time in the internal network.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any compromised resource in the unfiltered subnet.",
			LateralMovement:    "Unrestricted east-west TCP/UDP across the subnet and peered networks.",
			MaxPrivilege:       "Whatever privilege any neighbour in the subnet holds.",
			DataAtRisk:         []string{"Internal databases", "File shares", "Internal web apps", "Service endpoints reachable from the subnet"},
			ServicesAtRisk:     []string{"All VMs and PaaS-injected endpoints in the subnet"},
			EstimatedScopePerc: "Entire subnet + any peered network without its own NSG",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "1.3 / 10.2", Impact: "Network segmentation is not enforced and audit trails for network access do not exist."},
			{Framework: "NIST 800-53", Control: "SC-7 / AU-12", Impact: "Boundary protection is absent on the subnet and audit event generation is not configured."},
			{Framework: "ISO 27001:2022", Control: "A.8.22 / A.8.15", Impact: "Network segregation and logging controls are not in place."},
		},
		MinimalFixSet: []string{"zt_net_003", "zt_vis_006"},
		PriorityFix: "Attach a deny-by-default NSG to the subnet first - this immediately constrains lateral movement even before you have logs. Enable flow logs to the Network Watcher workspace in parallel.",
		BreakingNote: "Applying a deny-by-default NSG can break undocumented east-west dependencies (backup agents, monitoring pollers). Start with an allow-listed NSG derived from flow log baselines, then tighten.",
		MITRETechnique:    "T1046 / T1562.008",
		MITRETactic:       "Discovery / Defense Evasion",
		KillChainPhase:    "Lateral Movement",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-008: Defender disabled open ports to blind execution
// ---------------------------------------------------------------------------

func buildChain008(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_vis_003", "zt_net_001", "zt_net_002", "zt_vis_002")
	triggers := collectFindingIDs(findings, "zt_vis_003", "zt_net_001", "zt_net_002", "zt_vis_002")

	return &models.AttackChain{
		ID:                 "CHAIN-008",
		Title:              "Defender disabled open ports to blind execution",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Microsoft Defender for Cloud Servers plan is turned off, management ports are open to the internet, and activity logs are not shipped to a SIEM. " +
			"An attacker brute-forces or exploits the exposed port, executes payloads on the VM, and neither the host-based Defender sensor nor the control-plane audit trail reports anything. " +
			"The environment becomes a blind spot: compromise happens in full darkness.",
		TriggerFindings: triggers,
		TriggerLogic:    "ANCHOR_PLUS_ONE",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Locate a VM exposing SSH/RDP/WinRM to the internet.",
				Technical: "Shodan / internet-wide TLS banner scan; NSG permits 0.0.0.0/0 on port 22 or 3389.",
				Technique: "T1595.001",
				EnabledBy: "zt_net_001",
				Gain:      "Reachable compromise target.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Exploit or brute-force the exposed service to gain interactive access.",
				Technical: "Credential spray against local accounts; or exploitation of unpatched SSH/RDP CVEs.",
				Technique: "T1110.003",
				EnabledBy: "zt_net_002",
				Gain:      "Shell on the VM as a local user.",
			},
			{
				Number:    3,
				Actor:     "Attacker on VM",
				Action:    "Execute tooling with zero host-level detection.",
				Technical: "Defender for Servers plan is Free/off: no MDE sensor, no file behaviour monitoring, no EDR telemetry generated.",
				Technique: "T1562.001",
				EnabledBy: "zt_vis_003",
				Gain:      "Unobserved execution of discovery, credential dumping, and persistence tools.",
			},
			{
				Number:    4,
				Actor:     "Attacker on VM",
				Action:    "Operate without control-plane telemetry either - Activity Log is not exported to a SIEM.",
				Technical: "No diagnosticSettings streaming to Log Analytics / Event Hub; on-box actions translated into ARM calls are not correlated anywhere.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_002",
				Gain:      "Complete blind spot across both host and cloud audit surfaces.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Internet-exposed management port on an unmonitored VM.",
			LateralMovement:    "Whatever the compromised VM can reach - and nobody will see it happening.",
			MaxPrivilege:       "Local admin on the VM; potentially more via managed identity (see CHAIN-001).",
			DataAtRisk:         []string{"Everything on the VM and everything reachable from it"},
			ServicesAtRisk:     []string{"Compute", "Any service the VM can call"},
			EstimatedScopePerc: "Unknown - the absence of telemetry is the finding",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "SOC 2", Control: "CC7.2 / CC7.3", Impact: "The entity does not monitor system components for anomalies and does not evaluate security events."},
			{Framework: "PCI DSS 4.0", Control: "10.2 / 11.5", Impact: "Audit logs and change-detection mechanisms are not implemented on systems handling cardholder data."},
			{Framework: "ISO 27001:2022", Control: "A.8.16 / A.8.15", Impact: "Monitoring activities and logging are not performed on information systems."},
		},
		MinimalFixSet: []string{"zt_vis_003", "zt_net_001"},
		PriorityFix: "Enable Defender for Servers Plan 2 (or at minimum Plan 1) tenant-wide. Restoring telemetry gives retroactive context for the other findings.",
		BreakingNote: "Defender for Servers incurs per-node cost. Budget must be aligned before rollout; for short-term mitigation enable auto-provisioning of the Log Analytics agent as a partial measure.",
		MITRETechnique:    "T1562.001 / T1190",
		MITRETactic:       "Defense Evasion / Initial Access",
		KillChainPhase:    "Command and Control",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-009: KeyVault no protection no alerts to ransomware
// ---------------------------------------------------------------------------

func buildChain009(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_004", "zt_data_005", "zt_vis_004")
	triggers := collectFindingIDs(findings, "zt_data_004", "zt_data_005", "zt_vis_004")

	return &models.AttackChain{
		ID:                 "CHAIN-009",
		Title:              "KeyVault no protection no alerts to ransomware",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "A Key Vault has purge protection disabled, soft-delete retention at a minimal window, and no action-group alerts on vault operations. " +
			"An attacker - or a malicious insider - who gets Key Vault Contributor can delete and purge every secret and key. " +
			"Any service encrypting data with a customer-managed key in that vault instantly loses access to the data: a cloud-native ransomware outcome with no ransom to pay because the keys are simply gone.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker / insider with Key Vault Contributor",
				Action:    "Enumerate the target Key Vault and confirm purge protection is off.",
				Technical: "az keyvault show returns enablePurgeProtection=false and a low softDeleteRetentionInDays.",
				Technique: "T1087.004",
				EnabledBy: "zt_data_004",
				Gain:      "Confirmation that delete + purge is a one-way operation.",
			},
			{
				Number:    2,
				Actor:     "Attacker / insider",
				Action:    "Delete every secret, key, and certificate in the vault.",
				Technical: "az keyvault secret delete / key delete looped across the vault inventory.",
				Technique: "T1485",
				EnabledBy: "zt_data_005",
				Gain:      "Vault content moved to soft-delete state.",
			},
			{
				Number:    3,
				Actor:     "Attacker / insider",
				Action:    "Purge the soft-deleted items so recovery is impossible.",
				Technical: "az keyvault secret purge / key purge - succeeds because purge protection is disabled.",
				Technique: "T1485",
				EnabledBy: "zt_data_005",
				Gain:      "Permanent destruction of cryptographic material.",
			},
			{
				Number:    4,
				Actor:     "Attacker / insider",
				Action:    "Operate without alerting - no action groups subscribe to vault audit events.",
				Technical: "No alert rule on AuditEvent category for Microsoft.KeyVault; no Logic App or email fires on bulk delete.",
				Technique: "T1562.006",
				EnabledBy: "zt_vis_004",
				Gain:      "Detection happens only when downstream apps start failing - hours to days later.",
			},
			{
				Number:    5,
				Actor:     "Business impact",
				Action:    "Every service encrypting data with a customer-managed key in that vault becomes unreadable.",
				Technical: "Storage / SQL / Disk encryption with CMK → cryptographic key version unresolvable → I/O fails.",
				Technique: "T1486",
				EnabledBy: "zt_data_004",
				Gain:      "Effective ransomware outcome: data is still on disk but cryptographically inaccessible, and no attacker to pay.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any principal with Key Vault Contributor or equivalent purge rights.",
			LateralMovement:    "Not required - single-shot destructive operation.",
			MaxPrivilege:       "Key Vault data-plane destruction with no recovery path.",
			DataAtRisk:         []string{"All CMK-protected storage accounts", "All CMK-protected SQL databases", "All disk-encrypted VMs using the vault"},
			ServicesAtRisk:     []string{"Key Vault", "Storage", "SQL", "VM Disk Encryption", "Any service consuming the vault's CMK"},
			EstimatedScopePerc: "Every workload binding to the affected vault",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "ISO 27001:2022", Control: "A.8.24 / A.8.13", Impact: "Use of cryptography and information backup controls fail; keys are not protected against destruction."},
			{Framework: "NIST 800-53", Control: "SC-12 / CP-9", Impact: "Cryptographic key establishment and management and system backup requirements are not met."},
			{Framework: "HIPAA", Control: "164.312(a)(2)(iv)", Impact: "Encryption and decryption requirement fails when keys are destroyed without recovery."},
		},
		MinimalFixSet: []string{"zt_data_004", "zt_vis_004"},
		PriorityFix: "Enable purge protection on every Key Vault (it cannot be disabled once on - this is a one-way safety switch). Configure action-group alerts on vault delete/purge operations.",
		BreakingNote: "Purge protection cannot be turned off once enabled. Ensure legitimate key-rotation workflows use version retirement rather than secret deletion before flipping the switch.",
		MITRETechnique:    "T1485 / T1486",
		MITRETactic:       "Impact",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-010: No private endpoint SQL all IPs no audit to DB breach
// ---------------------------------------------------------------------------

func buildChain010(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_010", "zt_data_007", "zt_data_003")
	triggers := collectFindingIDs(findings, "zt_net_010", "zt_data_007", "zt_data_003")

	return &models.AttackChain{
		ID:                 "CHAIN-010",
		Title:              "No private endpoint SQL all IPs no audit to DB breach",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An Azure SQL logical server has no Private Endpoint, its firewall rule allows 0.0.0.0 - 255.255.255.255, and SQL Auditing is not enabled. " +
			"The server accepts TDS from anywhere, SQL authentication is allowed, and nothing logs connection attempts. " +
			"A credential-stuffing attacker finds the server via SQL DNS enumeration, authenticates with leaked credentials, and exfiltrates the database - silently.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Enumerate *.database.windows.net via DNS to discover reachable SQL servers.",
				Technical: "Wordlist brute-force against *.database.windows.net; live servers resolve.",
				Technique: "T1590.002",
				EnabledBy: "zt_net_010",
				Gain:      "List of reachable Azure SQL endpoints.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Connect from any internet IP to the server because the firewall allows 0.0.0.0-255.255.255.255.",
				Technical: "AllowAzureServices=true and a firewall rule StartIpAddress=0.0.0.0, EndIpAddress=255.255.255.255.",
				Technique: "T1133",
				EnabledBy: "zt_data_007",
				Gain:      "TDS connectivity from arbitrary source IPs.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Authenticate with credentials from a public leak or low-privilege helpdesk compromise.",
				Technical: "SQL Authentication is enabled on the server (not Entra-only); credential stuffing against sqladmin, dbadmin, sa accounts.",
				Technique: "T1078",
				EnabledBy: "zt_data_007",
				Gain:      "Authenticated SQL session.",
			},
			{
				Number:    4,
				Actor:     "Attacker in SQL",
				Action:    "Exfiltrate entire tables with no trace.",
				Technical: "SELECT * against PII/PCI tables; SQL Auditing is not enabled and no Extended Events are writing to storage.",
				Technique: "T1530",
				EnabledBy: "zt_data_003",
				Gain:      "Silent bulk exfiltration of customer records.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any internet IP with credentials for the SQL server.",
			LateralMovement:    "Into every database on the server; cross-database queries where permitted.",
			MaxPrivilege:       "Whatever role the compromised SQL login holds - potentially db_owner.",
			DataAtRisk:         []string{"Customer PII", "Transaction records", "Any data in databases on the affected logical server"},
			ServicesAtRisk:     []string{"Azure SQL Database", "Any downstream reports or analytics sourced from the database"},
			EstimatedScopePerc: "Every database on the affected logical server",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "1.3 / 10.2", Impact: "Network segmentation and audit logging requirements for systems processing cardholder data are not satisfied."},
			{Framework: "GDPR", Control: "Article 32", Impact: "Appropriate security of processing fails: personal data is directly reachable from the internet without access logging."},
			{Framework: "HIPAA", Control: "164.312(b) / 164.312(e)(1)", Impact: "Audit controls and transmission security fail when SQL auditing is absent and any network can reach ePHI."},
		},
		MinimalFixSet: []string{"zt_net_010", "zt_data_007"},
		PriorityFix: "Remove the 0.0.0.0-255.255.255.255 firewall rule and attach a Private Endpoint; enable SQL Auditing in parallel so the next attempt is detected.",
		BreakingNote: "Applications that currently connect to Azure SQL over the public endpoint from on-prem or third-party CIDRs must be migrated to Private Link with DNS forwarders, or given explicit allow-listed NAT IPs.",
		MITRETechnique:    "T1190 / T1530",
		MITRETactic:       "Initial Access / Collection",
		KillChainPhase:    "Exfiltration",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-011: Cross-tenant unrestricted no CAP to multi-tenant breach
// ---------------------------------------------------------------------------

func buildChain011(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_004", "zt_id_006", "zt_vis_005")
	triggers := collectFindingIDs(findings, "zt_id_004", "zt_id_006", "zt_vis_005")

	return &models.AttackChain{
		ID:                 "CHAIN-011",
		Title:              "Cross-tenant unrestricted no CAP to multi-tenant breach",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Cross-tenant access settings are left at the Microsoft defaults (inbound from any tenant allowed), no Conditional Access policy scopes access by tenant or device compliance, " +
			"and sign-in logs are not forwarded to a SIEM. An attacker who compromises any identity in any external tenant can B2B-collaborate into the victim tenant " +
			"and - because no CA policy blocks it - access shared resources with the compromised credential. The source sign-ins look foreign but nothing is watching.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Compromise any user in an unrelated Entra ID tenant (phishing, token theft, adversary-in-the-middle).",
				Technical: "Evilginx-style AiTM capture against a small tenant that trusts the target via B2B.",
				Technique: "T1566.001",
				EnabledBy: "zt_id_004",
				Gain:      "Valid session token in a trusted third-party tenant.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Pivot to the victim tenant via unrestricted cross-tenant access.",
				Technical: "crossTenantAccessPolicy default configuration permits inbound B2B collaboration from any tenant; attacker's external identity resolves into the target directory.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_004",
				Gain:      "Guest or external member access to shared resources in the victim tenant.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Bypass conditional controls because no CA policy requires device compliance or tenant scoping.",
				Technical: "No policy with 'Include: All external users' + 'Require compliant device' or 'Block unknown tenant'.",
				Technique: "T1562.007",
				EnabledBy: "zt_id_006",
				Gain:      "Token issuance without any risk-based or device-based gate.",
			},
			{
				Number:    4,
				Actor:     "External attacker",
				Action:    "Evade detection because sign-in logs are not ingested into a SIEM for correlation.",
				Technical: "Diagnostic setting for SignInLogs is not enabled on Azure AD; logs live for 30 days and nobody queries them.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_005",
				Gain:      "The anomalous foreign-tenant sign-in is never alerted on.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Compromised identity in any external Entra tenant.",
			LateralMovement:    "B2B collaboration → shared resource access → internal data via guest permissions.",
			MaxPrivilege:       "Whatever scope the guest is granted - often higher than intended because guest permissions default to full directory read.",
			DataAtRisk:         []string{"Shared SharePoint libraries", "Teams channels", "Resources explicitly shared with external users"},
			ServicesAtRisk:     []string{"Entra ID", "SharePoint Online", "Teams", "Any resource with external principals in its RBAC"},
			EstimatedScopePerc: "Every resource shared with external identities",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "ISO 27001:2022", Control: "A.5.19 / A.5.20", Impact: "Information security in supplier and third-party relationships is not managed; default trust to all tenants is excessive."},
			{Framework: "SOC 2", Control: "CC6.1 / CC6.3", Impact: "Logical access to external parties is not restricted based on business need."},
			{Framework: "NIST 800-53", Control: "AC-4 / AC-20", Impact: "Information flow enforcement and use of external information systems are not controlled."},
		},
		MinimalFixSet: []string{"zt_id_004", "zt_id_006"},
		PriorityFix: "Switch cross-tenant access settings to 'block inbound by default' and explicitly allow-list partner tenants. Add a CA policy requiring compliant device or MFA for external users.",
		BreakingNote: "Locking down cross-tenant access will break ad-hoc B2B collaboration with partners whose tenants are not yet allow-listed. Publish the allow-list process before the cutover.",
		MITRETechnique:    "T1078.004 / T1562.007",
		MITRETactic:       "Initial Access / Defense Evasion",
		KillChainPhase:    "Initial Access",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-012: Function no auth system identity to serverless escalation
// ---------------------------------------------------------------------------

func buildChain012(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_004", "zt_wl_010", "zt_vis_001")
	triggers := collectFindingIDs(findings, "zt_wl_004", "zt_wl_010", "zt_vis_001")

	return &models.AttackChain{
		ID:                 "CHAIN-012",
		Title:              "Function no auth system identity to serverless escalation",
		Severity:           "HIGH",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An Azure Function App is publicly reachable with Anonymous authLevel, it has a System-Assigned Managed Identity with broad RBAC, and diagnostic logging is disabled on the host. " +
			"An attacker who locates the function URL calls the IMDS-equivalent from inside the function code path (or exploits an SSRF in the function logic) " +
			"and steals a managed identity token that unlocks downstream services. The platform logs that would reveal the call were never captured.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Discover the Function App URL via *.azurewebsites.net enumeration or GitHub search.",
				Technical: "Subdomain enumeration + unauthenticated GET /api/{function} returns 200.",
				Technique: "T1595.002",
				EnabledBy: "zt_wl_004",
				Gain:      "A reachable, unauthenticated function endpoint.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Coerce the function to return its managed identity token via SSRF or dump endpoint.",
				Technical: "Many functions include a diagnostics/debug endpoint that reflects environment; IDENTITY_ENDPOINT + IDENTITY_HEADER can be invoked to fetch a token.",
				Technique: "T1552.005",
				EnabledBy: "zt_wl_010",
				Gain:      "Managed identity bearer token scoped to whatever the function identity holds.",
			},
			{
				Number:    3,
				Actor:     "Attacker with MI token",
				Action:    "Enumerate and consume downstream services with the stolen token.",
				Technical: "az rest calls against Storage, Key Vault, Graph - the identity often has Storage Blob Data Contributor at subscription scope.",
				Technique: "T1078.004",
				EnabledBy: "zt_wl_010",
				Gain:      "Unauthorised access to storage, secrets, or Graph, depending on the identity's role assignments.",
			},
			{
				Number:    4,
				Actor:     "External attacker",
				Action:    "Operate without telemetry - Function App diagnostic settings are not enabled.",
				Technical: "FunctionAppLogs not streamed to Log Analytics; request logs absent; attack is only visible in Application Insights if it was configured.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_001",
				Gain:      "No record of the invocation or token request.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Unauthenticated HTTPS call to a public Function App endpoint.",
			LateralMovement:    "Stolen managed identity token → downstream Azure services.",
			MaxPrivilege:       "Whatever the function's Managed Identity holds (often over-scoped: Contributor at resource group or subscription).",
			DataAtRisk:         []string{"Storage accounts accessible to the identity", "Key Vault secrets", "Any service the identity has RBAC on"},
			ServicesAtRisk:     []string{"Azure Functions", "Storage", "Key Vault", "Resource Manager"},
			EstimatedScopePerc: "Blast radius of the function's managed identity",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "8.3 / 10.2", Impact: "Strong authentication for non-console access and audit trails for function invocations are not implemented."},
			{Framework: "SOC 2", Control: "CC6.1 / CC7.2", Impact: "Logical access and anomaly monitoring on serverless workloads fail."},
			{Framework: "ISO 27001:2022", Control: "A.8.3 / A.8.16", Impact: "Information access restriction and monitoring activities are not enforced on the function."},
		},
		MinimalFixSet: []string{"zt_wl_004", "zt_vis_001"},
		PriorityFix: "Set function authLevel to 'function' or 'admin' and place the function behind APIM or Front Door with WAF. Right-size the managed identity role assignments next.",
		BreakingNote: "Changing authLevel requires every caller to supply a function key or Entra token; update clients (and any public documentation) before deploying.",
		MITRETechnique:    "T1190 / T1552.005",
		MITRETactic:       "Initial Access / Credential Access",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-013: VNet peering no firewall to east-west compromise
// ---------------------------------------------------------------------------

func buildChain013(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_004", "zt_net_005", "zt_vis_006")
	triggers := collectFindingIDs(findings, "zt_net_004", "zt_net_005", "zt_vis_006")

	return &models.AttackChain{
		ID:                 "CHAIN-013",
		Title:              "VNet peering no firewall to east-west compromise",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Multiple VNets are peered directly to each other with AllowForwardedTraffic enabled, there is no Azure Firewall or NVA inspecting east-west traffic, " +
			"and NSG Flow Logs are not configured. A compromise in any peered VNet immediately becomes a compromise of every peered VNet - " +
			"production, non-production, and shared services are all one flat network as far as an attacker is concerned.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker in non-prod VNet",
				Action:    "Enumerate peered VNets via Azure Resource Graph or DNS reconnaissance.",
				Technical: "Resources.network.virtualNetworks/peerings lists the target prod VNet and confirms allowForwardedTraffic=true.",
				Technique: "T1590.004",
				EnabledBy: "zt_net_004",
				Gain:      "Full map of peering topology.",
			},
			{
				Number:    2,
				Actor:     "Attacker in non-prod VNet",
				Action:    "Route directly to production IPs without any firewall inspection.",
				Technical: "No 0.0.0.0/0 UDR pointing at Azure Firewall; no NVA in the data path; traffic flows over the peering link unfiltered.",
				Technique: "T1021",
				EnabledBy: "zt_net_005",
				Gain:      "Direct layer-4 reach to production services.",
			},
			{
				Number:    3,
				Actor:     "Attacker in prod VNet",
				Action:    "Move laterally and exfiltrate data while no flow logs are captured.",
				Technical: "Flow logs v2 not enabled on the NSGs protecting target resources; east-west traffic is invisible.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_006",
				Gain:      "Silent lateral movement into the production tier.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any compromised workload in a peered VNet.",
			LateralMovement:    "Direct IP routing across all peered VNets, unfiltered.",
			MaxPrivilege:       "Whatever the attacker can reach in the destination VNet(s).",
			DataAtRisk:         []string{"All resources in peered VNets", "Cross-environment data (prod/non-prod)"},
			ServicesAtRisk:     []string{"Every VNet-integrated service across the peering mesh"},
			EstimatedScopePerc: "Entire peering mesh",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "1.3 / 1.4", Impact: "Network segmentation between CDE and non-CDE environments fails."},
			{Framework: "ISO 27001:2022", Control: "A.8.22 / A.8.23", Impact: "Network segregation and access to networks are not controlled."},
			{Framework: "NIST 800-53", Control: "SC-7(4) / SC-7(5)", Impact: "External and internal boundary protection is absent on the peering links."},
		},
		MinimalFixSet: []string{"zt_net_005"},
		PriorityFix: "Insert an Azure Firewall in a hub-and-spoke topology and force all inter-VNet traffic through it via UDRs. Disable direct peerings where possible.",
		BreakingNote: "Introducing a firewall in the data path changes latency characteristics and may break applications that rely on specific source IPs. Model traffic with the firewall in audit mode first.",
		MITRETechnique:    "T1021 / T1590.004",
		MITRETactic:       "Lateral Movement / Discovery",
		KillChainPhase:    "Lateral Movement",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-014: No backup public storage to ransomware no recovery
// ---------------------------------------------------------------------------

func buildChain014(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_008", "zt_data_001", "zt_net_009")
	triggers := collectFindingIDs(findings, "zt_data_008", "zt_data_001", "zt_net_009")

	return &models.AttackChain{
		ID:                 "CHAIN-014",
		Title:              "No backup public storage to ransomware no recovery",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Critical storage holds no geo-redundant backup or soft-delete configuration, the account permits public blob access, and outbound egress from any VM in the environment is unrestricted. " +
			"An attacker encrypts or overwrites the blobs (ransomware), and because there is no backup tier and no versioning, the only copy of the data is the encrypted one. " +
			"Payment becomes the only option.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Discover the public storage account and identify writable containers.",
				Technical: "DNS brute-force against *.blob.core.windows.net; PUT probe reveals container-level public write or recoverable credentials.",
				Technique: "T1580",
				EnabledBy: "zt_data_001",
				Gain:      "Confirmed writable target.",
			},
			{
				Number:    2,
				Actor:     "Attacker with writable blob access",
				Action:    "Encrypt every blob in place with attacker-controlled keys.",
				Technical: "Download, AES-encrypt, PUT back; soft-delete is either off or short enough to expire during the operation.",
				Technique: "T1486",
				EnabledBy: "zt_data_008",
				Gain:      "Irrecoverable encryption of production data.",
			},
			{
				Number:    3,
				Actor:     "Attacker",
				Action:    "Exfiltrate a copy via unrestricted egress for double-extortion leverage.",
				Technical: "Outbound NSG allows egress to attacker CDN; data is streamed out before encryption.",
				Technique: "T1048.003",
				EnabledBy: "zt_net_009",
				Gain:      "Stolen copy available for sale / extortion in addition to the local encryption.",
			},
			{
				Number:    4,
				Actor:     "Business",
				Action:    "Attempt recovery and fail.",
				Technical: "No geo-redundant backup, no immutable blob policy, no snapshot history; blob versioning disabled.",
				Technique: "T1490",
				EnabledBy: "zt_data_008",
				Gain:      "Recovery is impossible without paying the ransom.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Public or weakly-authenticated blob access.",
			LateralMovement:    "Not required - a single storage account is the target.",
			MaxPrivilege:       "Full write/delete on the storage data set.",
			DataAtRisk:         []string{"All blobs in the exposed account(s)", "Backups that do not exist", "Application state"},
			ServicesAtRisk:     []string{"Azure Storage", "Every application reading from the affected containers"},
			EstimatedScopePerc: "100% of the data in the affected storage account",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "ISO 27001:2022", Control: "A.8.13 / A.5.30", Impact: "Information backup and ICT readiness for business continuity are absent."},
			{Framework: "NIST 800-53", Control: "CP-9 / CP-10", Impact: "System backup and recovery requirements are not met."},
			{Framework: "HIPAA", Control: "164.308(a)(7)", Impact: "Contingency plan requirements for ePHI backup and disaster recovery fail."},
		},
		MinimalFixSet: []string{"zt_data_008", "zt_data_001"},
		PriorityFix: "Enable blob soft-delete + versioning + immutable storage policy on every critical container; combine with GRS/RA-GRS redundancy. Disable public access in parallel.",
		BreakingNote: "Immutable storage policies cannot be shortened once set; plan the retention window carefully. Versioning increases storage cost and may require lifecycle management tuning.",
		MITRETechnique:    "T1486 / T1490",
		MITRETactic:       "Impact",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-015: App Service HTTP remote debug to credential intercept
// ---------------------------------------------------------------------------

func buildChain015(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_005", "zt_wl_008", "zt_data_009")
	triggers := collectFindingIDs(findings, "zt_wl_005", "zt_wl_008", "zt_data_009")

	return &models.AttackChain{
		ID:                 "CHAIN-015",
		Title:              "App Service HTTP remote debug to credential intercept",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An App Service still accepts HTTP (httpsOnly=false), remote debugging is enabled on the production slot, and its outbound connections to a backing database are not TLS-enforced. " +
			"An attacker positioned on the path (or sharing the network) captures the plaintext session, uses the remote debug channel to inject into the worker process, and steals the database connection string.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Network-positioned attacker",
				Action:    "Intercept unencrypted requests to the App Service hostname.",
				Technical: "httpsOnly=false means HTTP is served; attacker on a transit network downgrade-attacks session cookies.",
				Technique: "T1557.001",
				EnabledBy: "zt_wl_005",
				Gain:      "Session cookies and app secrets in transit.",
			},
			{
				Number:    2,
				Actor:     "Attacker with cookies",
				Action:    "Attach to the app worker via remote debugging.",
				Technical: "Visual Studio remote debug over 4020/4022 enabled; auth is the publish profile credential which was harvested in step 1.",
				Technique: "T1612",
				EnabledBy: "zt_wl_008",
				Gain:      "Live process debugger attached to the production app.",
			},
			{
				Number:    3,
				Actor:     "Attacker in process",
				Action:    "Extract the database connection string from process memory.",
				Technical: "Dump of process environment / app settings; connection string uses SQL auth and is in the clear.",
				Technique: "T1555",
				EnabledBy: "zt_data_009",
				Gain:      "Database credentials.",
			},
			{
				Number:    4,
				Actor:     "Attacker with DB creds",
				Action:    "Connect to the backing database over a non-TLS-enforced path and exfiltrate data.",
				Technical: "Connection policy does not require encryption; sniffed or replayed traffic to the DB tier.",
				Technique: "T1040",
				EnabledBy: "zt_data_009",
				Gain:      "Direct read of backend data with intercepted credentials.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Man-in-the-middle position on the path to the App Service.",
			LateralMovement:    "Process attach → app secrets → backend database.",
			MaxPrivilege:       "Whatever the database login holds - commonly db_owner on the app's database.",
			DataAtRisk:         []string{"Session cookies", "App settings / connection strings", "Backend database contents"},
			ServicesAtRisk:     []string{"App Service", "Azure SQL / backing database", "Any downstream API whose creds were in app settings"},
			EstimatedScopePerc: "App Service + any database it can reach",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "4.2 / 2.3", Impact: "Strong cryptography on public networks and secure configuration standards are not followed."},
			{Framework: "NIST 800-53", Control: "SC-8 / SC-13", Impact: "Transmission confidentiality and cryptographic protection requirements fail."},
			{Framework: "ISO 27001:2022", Control: "A.8.24 / A.8.25", Impact: "Use of cryptography and secure development lifecycle controls are not enforced."},
		},
		MinimalFixSet: []string{"zt_wl_005", "zt_wl_008"},
		PriorityFix: "Set httpsOnly=true and disable remote debugging on all slots. Migrate the database connection string to a managed identity + Key Vault reference.",
		BreakingNote: "Legacy clients that cannot negotiate HTTPS will be rejected after the flag flips. Remote debugging in production is almost always an oversight left over from initial deployment.",
		MITRETechnique:    "T1557 / T1555",
		MITRETactic:       "Credential Access / Collection",
		KillChainPhase:    "Credential Access",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-016: No JIT open ports no alert to persistent backdoor
// ---------------------------------------------------------------------------

func buildChain016(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_vis_010", "zt_net_001", "zt_vis_008")
	triggers := collectFindingIDs(findings, "zt_vis_010", "zt_net_001", "zt_vis_008")

	return &models.AttackChain{
		ID:                 "CHAIN-016",
		Title:              "No JIT open ports no alert to persistent backdoor",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Just-in-Time VM access is not enabled, NSGs allow management ports from the internet permanently, and there are no alerts on NSG rule additions. " +
			"An attacker who gains initial access can add a new NSG rule to open any port they choose - creating a durable backdoor - and the platform never fires an alert. " +
			"The victim has replaced a time-bound access gate with a permanent freeway.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Access an internet-exposed management port with stolen credentials or CVE exploitation.",
				Technical: "NSG rule allows *:22 or *:3389 inbound; JIT would have required approval and time-bounded it but is not enabled.",
				Technique: "T1190",
				EnabledBy: "zt_net_001",
				Gain:      "Initial access on the VM.",
			},
			{
				Number:    2,
				Actor:     "Attacker on VM",
				Action:    "Add a new NSG rule opening an additional unusual port for a persistent callback channel.",
				Technical: "Using the host's managed identity (or compromised admin) call az network nsg rule create --destination-port-ranges 12345.",
				Technique: "T1133",
				EnabledBy: "zt_vis_010",
				Gain:      "Durable ingress on an obscure port that survives rotation of the original credential.",
			},
			{
				Number:    3,
				Actor:     "Attacker",
				Action:    "Operate without alerting on NSG changes.",
				Technical: "No alert rule on Microsoft.Network/networkSecurityGroups/securityRules/write; no policy denies the operation; change blends into noise.",
				Technique: "T1562.001",
				EnabledBy: "zt_vis_008",
				Gain:      "Undetected persistence for weeks or months.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Internet-exposed management port.",
			LateralMovement:    "Persistent backdoor → whatever the backdoored VM can reach.",
			MaxPrivilege:       "Persistent VM control + ability to mutate NSGs.",
			DataAtRisk:         []string{"Data reachable from the VM", "Credentials cached on the VM"},
			ServicesAtRisk:     []string{"Compute", "Network", "Any internal service reachable from the VM"},
			EstimatedScopePerc: "VM and its lateral reachable set over time",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "AC-2(11) / SI-4", Impact: "Usage restrictions and information system monitoring for anomalous behaviour are not enforced."},
			{Framework: "ISO 27001:2022", Control: "A.8.16 / A.5.25", Impact: "Monitoring and incident response readiness fail."},
			{Framework: "SOC 2", Control: "CC7.2", Impact: "System activities are not monitored for security events and unauthorized changes."},
		},
		MinimalFixSet: []string{"zt_vis_010", "zt_net_001"},
		PriorityFix: "Enable Defender for Cloud JIT on all VMs and remove standing NSG allow rules for management ports. Add an activity log alert on NSG rule creation.",
		BreakingNote: "JIT requires users to request access through Defender, which changes the admin workflow. Communicate the change and document the request process before rollout.",
		MITRETechnique:    "T1133 / T1562.001",
		MITRETactic:       "Persistence / Defense Evasion",
		KillChainPhase:    "Persistence",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-017: Guest unrestricted no reviews to long-term persistence
// ---------------------------------------------------------------------------

func buildChain017(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_009", "zt_id_010", "zt_vis_004")
	triggers := collectFindingIDs(findings, "zt_id_009", "zt_id_010", "zt_vis_004")

	return &models.AttackChain{
		ID:                 "CHAIN-017",
		Title:              "Guest unrestricted no reviews to long-term persistence",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Guest user permissions are left at the Microsoft default of 'Same as member users', no access reviews fire on guest accounts, and no alerts fire when guests are added. " +
			"A guest identity added during a short consulting engagement becomes a permanent foothold: the guest can enumerate the directory, and nobody ever removes them.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker (former contractor)",
				Action:    "Retain guest credentials long after engagement ends.",
				Technical: "Guest invitation never rescinded; no offboarding process; account still active in directory.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_009",
				Gain:      "Persistent authenticated identity in the victim tenant.",
			},
			{
				Number:    2,
				Actor:     "Guest attacker",
				Action:    "Enumerate the directory like a member user because guest permissions are not restricted.",
				Technical: "Get-MgUser, Get-MgGroup succeed because externalUserState guest can read full directory objects.",
				Technique: "T1087.004",
				EnabledBy: "zt_id_009",
				Gain:      "Complete map of users, groups, and privileged role members.",
			},
			{
				Number:    3,
				Actor:     "Guest attacker",
				Action:    "Avoid removal because access reviews are not configured.",
				Technical: "Access Reviews for guest users are not enabled; no recertification fires.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_010",
				Gain:      "Indefinite persistence.",
			},
			{
				Number:    4,
				Actor:     "Guest attacker",
				Action:    "Evade detection because no alerts fire on privileged operations.",
				Technical: "No action group on AuditLog category AuditLogs for role assignments or group changes.",
				Technique: "T1562.006",
				EnabledBy: "zt_vis_004",
				Gain:      "Quiet escalation pathway into groups that grant resource access.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Dormant guest identity from a previous engagement.",
			LateralMovement:    "Directory enumeration → social engineering or self-service group join → resource access.",
			MaxPrivilege:       "Whatever groups / RBAC the guest is / becomes a member of.",
			DataAtRisk:         []string{"Directory information", "Any resource shared with Everyone/All Users", "Data in groups the guest can join"},
			ServicesAtRisk:     []string{"Entra ID", "SharePoint/Teams content shared with the guest"},
			EstimatedScopePerc: "Long-tail exposure across shared resources",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "ISO 27001:2022", Control: "A.5.18 / A.5.16", Impact: "Access rights and identity management for external parties are not properly managed."},
			{Framework: "SOC 2", Control: "CC6.2 / CC6.3", Impact: "User access termination and review of external access are not timely."},
			{Framework: "NIST 800-53", Control: "AC-2(2) / AC-2(3)", Impact: "Automated account management and disabling of inactive accounts are absent."},
		},
		MinimalFixSet: []string{"zt_id_009", "zt_id_010"},
		PriorityFix: "Restrict guest permissions to 'Most restrictive' at the tenant level and enable recurring access reviews on all guest users.",
		BreakingNote: "Restricting guest permissions may break collaboration scenarios where guests need to see group membership. Test against the most active partner tenants before enforcement.",
		MITRETechnique:    "T1078.004 / T1087.004",
		MITRETactic:       "Persistence / Discovery",
		KillChainPhase:    "Persistence",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-018: No WAF no DDoS no vuln assessment to app breach
// ---------------------------------------------------------------------------

func buildChain018(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_008", "zt_net_007", "zt_wl_006")
	triggers := collectFindingIDs(findings, "zt_net_008", "zt_net_007", "zt_wl_006")

	return &models.AttackChain{
		ID:                 "CHAIN-018",
		Title:              "No WAF no DDoS no vuln assessment to app breach",
		Severity:           "HIGH",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "A public-facing application has no WAF in front of it, no DDoS Standard protection on its public IP, and no vulnerability assessment runs against its images or code. " +
			"Attackers hit it with off-the-shelf web-app exploits, take it down with volumetric traffic on demand, and there is no upstream control that would have caught or absorbed any of it.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Scan the application with automated vulnerability tooling.",
				Technical: "Burp / ZAP against the public hostname; known CVEs in dependencies are identified because vuln assessment never caught them pre-deploy.",
				Technique: "T1595.002",
				EnabledBy: "zt_wl_006",
				Gain:      "List of exploitable vulnerabilities in the running application.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Exploit SQL injection / deserialization / SSRF without WAF interference.",
				Technical: "No Application Gateway WAF or Front Door WAF fronts the app; raw request reaches the origin.",
				Technique: "T1190",
				EnabledBy: "zt_net_008",
				Gain:      "Code execution or direct database access through the web tier.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Follow up with a volumetric DDoS as cover for the intrusion.",
				Technical: "DDoS Network Protection is Basic (free tier), no Standard plan; public IP absorbs no mitigation.",
				Technique: "T1498",
				EnabledBy: "zt_net_007",
				Gain:      "Defenders distracted by availability crisis during data theft.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Direct internet traffic to the application endpoint.",
			LateralMovement:    "Application foothold → backend services (DB, queues, caches).",
			MaxPrivilege:       "Application service account + anything it can reach.",
			DataAtRisk:         []string{"Customer data in the application database", "Uploaded files", "Session tokens"},
			ServicesAtRisk:     []string{"App Service / AKS ingress", "Backend databases", "Downstream APIs"},
			EstimatedScopePerc: "The application and its backing stores",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "6.4 / 11.3", Impact: "Public-facing web applications are not protected by a WAF and vulnerability assessments are not performed."},
			{Framework: "NIST 800-53", Control: "RA-5 / SC-5", Impact: "Vulnerability scanning and denial-of-service protection requirements fail."},
			{Framework: "ISO 27001:2022", Control: "A.8.8 / A.8.25", Impact: "Management of technical vulnerabilities and secure development lifecycle controls are absent."},
		},
		MinimalFixSet: []string{"zt_net_008", "zt_wl_006"},
		PriorityFix: "Place the application behind an Azure Front Door Premium or Application Gateway WAF in Prevention mode. Enable Defender for Cloud vuln assessment on the workload.",
		BreakingNote: "WAF in Prevention mode can block legitimate requests with unusual payloads. Run in Detection mode first, tune rules, then switch to Prevention.",
		MITRETechnique:    "T1190 / T1498",
		MITRETactic:       "Initial Access / Impact",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-019: Permanent privilege no PIM no reviews to insider threat
// ---------------------------------------------------------------------------

func buildChain019(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_003", "zt_id_007", "zt_id_010")
	triggers := collectFindingIDs(findings, "zt_id_003", "zt_id_007", "zt_id_010")

	return &models.AttackChain{
		ID:                 "CHAIN-019",
		Title:              "Permanent privilege no PIM no reviews to insider threat",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "This is the identity-only variant of CHAIN-004. Every layer of the privileged-identity lifecycle is missing: permanent role assignments exist, PIM is not configured as the enforcement path, " +
			"and no access reviews ever reconcile membership. A single malicious or compromised insider owns the tenant indefinitely, with no compensating control to limit blast radius or dwell time.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Privileged insider",
				Action:    "Hold a standing Global Administrator or User Access Administrator assignment.",
				Technical: "Role assignment with assignmentType=Active and no endDateTime; not brokered through PIM.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_003",
				Gain:      "24/7 privilege without activation friction.",
			},
			{
				Number:    2,
				Actor:     "Privileged insider",
				Action:    "Escalate further by assigning additional roles at will.",
				Technical: "PIM not enforced as the only path to privilege; role assignments created directly against role definitions.",
				Technique: "T1098.003",
				EnabledBy: "zt_id_007",
				Gain:      "Self-escalation to any directory or subscription role.",
			},
			{
				Number:    3,
				Actor:     "Privileged insider",
				Action:    "Remain in place for quarters because no access review catches the standing privilege.",
				Technical: "Access Reviews not enabled on directory roles or privileged groups.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_010",
				Gain:      "Indefinite dwell time.",
			},
			{
				Number:    4,
				Actor:     "Privileged insider",
				Action:    "Execute the intended impact at the time of their choosing.",
				Technical: "Bulk data export, selective destruction, credential theft - all permitted by standing privilege.",
				Technique: "T1485",
				EnabledBy: "zt_id_003",
				Gain:      "Whatever outcome the insider has planned - there is no guardrail.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any privileged insider account.",
			LateralMovement:    "Not required - standing privilege already spans the tenant.",
			MaxPrivilege:       "Global Administrator indefinitely.",
			DataAtRisk:         []string{"Entire tenant", "All subscriptions", "All Microsoft 365 data"},
			ServicesAtRisk:     []string{"Entra ID", "Every Azure subscription", "All Microsoft 365 workloads"},
			EstimatedScopePerc: "100% of the tenant",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "SOC 2", Control: "CC6.2 / CC6.3", Impact: "Separation of duties and periodic access reviews are not implemented."},
			{Framework: "ISO 27001:2022", Control: "A.5.15 / A.5.18", Impact: "Access control and rights management policies are not enforced for privileged roles."},
			{Framework: "NIST 800-53", Control: "AC-2(1) / AC-6(7) / AC-2(7)", Impact: "Automated account management, privileged role review, and least privilege are absent."},
		},
		MinimalFixSet: []string{"zt_id_007", "zt_id_010"},
		PriorityFix: "Enforce PIM as the only path to privileged roles; convert every active assignment to eligible; enable quarterly access reviews.",
		BreakingNote: "Enforcing PIM requires admins to activate roles before every operation and may break automated scripts that assume standing privilege. Break-glass accounts should remain active and excluded from reviews.",
		MITRETechnique:    "T1078.004 / T1098.003",
		MITRETactic:       "Persistence / Privilege Escalation",
		KillChainPhase:    "Privilege Escalation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-020: No Sentinel no diagnostics to invisible persistence
// ---------------------------------------------------------------------------

func buildChain020(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_vis_007", "zt_vis_001", "zt_vis_005")
	triggers := collectFindingIDs(findings, "zt_vis_007", "zt_vis_001", "zt_vis_005")

	return &models.AttackChain{
		ID:                 "CHAIN-020",
		Title:              "No Sentinel no diagnostics to invisible persistence",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "There is no Microsoft Sentinel workspace ingesting Azure telemetry, resource-level diagnostic settings are missing across the environment, and Entra ID sign-in and audit logs are not exported. " +
			"Any adversary that gains a foothold can establish persistence - service principals, app registrations, role assignments, resource changes - without any correlation or retention that would let defenders see it. " +
			"Sooner or later this becomes somebody else's incident report.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker with any initial access",
				Action:    "Enumerate and choose persistence techniques that leave telemetry only in places defenders are not watching.",
				Technical: "Service principal creation, app consent grants, role assignment changes - all emit AuditLogs events.",
				Technique: "T1098",
				EnabledBy: "zt_vis_007",
				Gain:      "Confidence that subsequent actions will not surface in any SIEM.",
			},
			{
				Number:    2,
				Actor:     "Attacker",
				Action:    "Create persistent backdoor service principal and grant it roles.",
				Technical: "New-MgServicePrincipal + New-MgRoleAssignment - events flow into AuditLogs but go nowhere.",
				Technique: "T1136.003",
				EnabledBy: "zt_vis_005",
				Gain:      "Durable non-human identity in the tenant.",
			},
			{
				Number:    3,
				Actor:     "Attacker",
				Action:    "Operate long-term across resources whose diagnostic settings are disabled.",
				Technical: "Storage, Key Vault, SQL audit logs not enabled; even on-resource anomalies are never captured.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_001",
				Gain:      "Persistent hands-on-keyboard access with no forensic trail.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any initial foothold - the chain is about what happens after.",
			LateralMovement:    "Anywhere, because nothing watches lateral movement.",
			MaxPrivilege:       "Whatever the attacker can gradually accumulate.",
			DataAtRisk:         []string{"Everything", "Retroactive investigation is impossible"},
			ServicesAtRisk:     []string{"All Azure and Entra services"},
			EstimatedScopePerc: "Unknown - no telemetry to size the blast radius",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "SOC 2", Control: "CC7.2 / CC7.3", Impact: "Monitoring and event evaluation requirements fail for the entire environment."},
			{Framework: "PCI DSS 4.0", Control: "10.2 / 10.5", Impact: "Audit trails for system components and secure retention are not implemented."},
			{Framework: "NIST 800-53", Control: "AU-6 / AU-12", Impact: "Audit record review, analysis, reporting, and generation are not in place."},
		},
		MinimalFixSet: []string{"zt_vis_007", "zt_vis_001"},
		PriorityFix: "Deploy Microsoft Sentinel onto a dedicated Log Analytics workspace and connect data sources starting with Entra ID SignInLogs, AuditLogs, and Azure Activity. Turn on diagnostic settings via Azure Policy deployIfNotExists.",
		BreakingNote: "Sentinel ingestion has ongoing cost. Start with critical sources and expand; use commitment tiers to control spend.",
		MITRETechnique:    "T1562.008 / T1098",
		MITRETactic:       "Defense Evasion / Persistence",
		KillChainPhase:    "Persistence",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-021: Public registry AKS public endpoint to supply chain
// ---------------------------------------------------------------------------

func buildChain021(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_002", "zt_wl_003", "zt_wl_007")
	triggers := collectFindingIDs(findings, "zt_wl_002", "zt_wl_003", "zt_wl_007")

	return &models.AttackChain{
		ID:                 "CHAIN-021",
		Title:              "Public registry AKS public endpoint to supply chain",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An Azure Container Registry allows anonymous pull, an AKS cluster pulling from it has a public API server, and pods are allowed to run privileged. " +
			"An attacker with anonymous push access (via a weak ACR policy or a compromised CI token) replaces a trusted image tag with a malicious one; " +
			"the next cluster deployment pulls it over the public network, runs it privileged, and the supply-chain foothold instantly becomes cluster-admin.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Supply-chain attacker",
				Action:    "Push a malicious image to a tag consumed by production workloads.",
				Technical: "ACR allows anonymous pull and has weak or missing push ACLs, or a compromised CI token is reused; image tag 'latest' is overwritten.",
				Technique: "T1195.002",
				EnabledBy: "zt_wl_002",
				Gain:      "Malicious image sitting at a trusted tag location.",
			},
			{
				Number:    2,
				Actor:     "AKS cluster",
				Action:    "Pulls the tainted image on next pod start and schedules it as a privileged pod.",
				Technical: "Public API server and public registry in the data path; no image signature verification (e.g., ratify/notary) enforced.",
				Technique: "T1059",
				EnabledBy: "zt_wl_003",
				Gain:      "Malicious container running inside the cluster.",
			},
			{
				Number:    3,
				Actor:     "Attacker inside container",
				Action:    "Escape to the node via privileged/hostPath mount and steal the kubelet managed identity.",
				Technical: "Pod spec permits privileged=true; mount /var/run/docker.sock or hostPath=/ to break out.",
				Technique: "T1611",
				EnabledBy: "zt_wl_007",
				Gain:      "Root on the node and access to the cluster identity token.",
			},
			{
				Number:    4,
				Actor:     "Attacker on node",
				Action:    "Pivot to ARM with the kubelet identity.",
				Technical: "IMDS token for the managed identity is used against Resource Manager; deployment control extends across the AKS resource group.",
				Technique: "T1078.004",
				EnabledBy: "zt_wl_007",
				Gain:      "Cluster + resource group compromise and a durable supply-chain vector.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Tainted image in a permissive or anonymously-writable registry.",
			LateralMovement:    "Container → privileged pod → node → ARM via managed identity.",
			MaxPrivilege:       "cluster-admin + whatever the node identity holds on the resource group.",
			DataAtRisk:         []string{"All cluster workloads", "All data cluster identities can reach", "Source code in mounted volumes"},
			ServicesAtRisk:     []string{"AKS", "ACR", "Resource Manager", "Downstream services consuming cluster output"},
			EstimatedScopePerc: "Cluster + its resource group",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "SA-12 / SR-3", Impact: "Supply chain protection and controls are not applied to container artifacts."},
			{Framework: "ISO 27001:2022", Control: "A.5.19 / A.8.30", Impact: "Supplier relationships and outsourced development controls fail when artifacts can be overwritten anonymously."},
			{Framework: "PCI DSS 4.0", Control: "6.3 / 2.2", Impact: "Secure configuration and development lifecycle controls are not applied to container images."},
		},
		MinimalFixSet: []string{"zt_wl_002", "zt_wl_007"},
		PriorityFix: "Disable anonymous pull on the registry, enforce content trust / image signing, and enforce PodSecurity 'restricted' in AKS so privileged escape paths close.",
		BreakingNote: "Enforcing signed images will block any workload whose images are not yet signed; stage the rollout by namespace. Disabling anonymous pull will break developers pulling without az login.",
		MITRETechnique:    "T1195.002 / T1611",
		MITRETactic:       "Initial Access / Privilege Escalation",
		KillChainPhase:    "Delivery",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-022: Emergency access lockout to tenant takeover
// ---------------------------------------------------------------------------

func buildChain022(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_012", "zt_id_014", "zt_id_021")
	triggers := collectFindingIDs(findings, "zt_id_012", "zt_id_014", "zt_id_021")

	return &models.AttackChain{
		ID:                 "CHAIN-022",
		Title:              "Emergency access lockout to tenant takeover",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "No break-glass (emergency access) accounts exist, admin roles are not protected by authentication strength policies, and PIM role activation requires no approval workflow. " +
			"An attacker who compromises any Global Administrator account - via token theft, phishing, or credential stuffing - can immediately activate every PIM-eligible role without a second human approving the request. " +
			"Because no break-glass accounts were provisioned, the legitimate tenant owners have no out-of-band recovery path once the attacker resets passwords, rotates MFA methods, and locks out the original admins. " +
			"The tenant is irrecoverable without Microsoft Support intervention, and the attacker has unrestricted dwell time.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Compromise a Global Administrator credential through phishing, token replay, or password spray.",
				Technical: "No authentication strength policy enforces phishing-resistant MFA (FIDO2/Windows Hello) for admin roles; legacy MFA methods (SMS, voice) are accepted.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_014",
				Gain:      "Valid session as a Global Administrator.",
			},
			{
				Number:    2,
				Actor:     "Attacker with admin session",
				Action:    "Activate all eligible PIM roles without any approval gate.",
				Technical: "PIM role settings have approvalRequired=false; activation is instant and self-service for all directory roles.",
				Technique: "T1098.003",
				EnabledBy: "zt_id_021",
				Gain:      "Full Global Administrator + every other directory role activated simultaneously.",
			},
			{
				Number:    3,
				Actor:     "Attacker with full privilege",
				Action:    "Reset passwords and MFA registrations for all other administrators.",
				Technical: "Reset-MgUserAuthenticationMethodPassword and Update-MgUserAuthenticationMethod for every admin UPN; existing admins locked out of their accounts.",
				Technique: "T1531",
				EnabledBy: "zt_id_021",
				Gain:      "All legitimate administrators are locked out of the tenant.",
			},
			{
				Number:    4,
				Actor:     "Attacker with sole control",
				Action:    "Add their own persistent credentials and federate an external IdP.",
				Technical: "New-MgDomainFederationConfiguration pointing to an attacker-controlled ADFS/SAML IdP; golden SAML attack path is now durable.",
				Technique: "T1484.002",
				EnabledBy: "zt_id_014",
				Gain:      "Persistent backdoor that survives individual credential rotation.",
			},
			{
				Number:    5,
				Actor:     "Legitimate tenant owners",
				Action:    "Attempt recovery and discover no break-glass accounts exist.",
				Technical: "No emergency access accounts with standing Global Administrator role, physical FIDO2 keys, and conditional access exclusions were provisioned per Microsoft best practice.",
				Technique: "T1531",
				EnabledBy: "zt_id_012",
				Gain:      "Recovery is impossible without filing a Microsoft Support ticket, which takes days.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any Global Administrator credential.",
			LateralMovement:    "Not required - full tenant control is immediate after PIM activation.",
			MaxPrivilege:       "Global Administrator with federation control - equivalent to owning the tenant.",
			DataAtRisk:         []string{"Entire Entra ID directory", "All Azure subscriptions", "All Microsoft 365 data", "All secrets in Key Vaults accessible via ARM"},
			ServicesAtRisk:     []string{"Entra ID", "All Azure subscriptions", "Microsoft 365", "Exchange Online", "SharePoint Online", "Teams"},
			EstimatedScopePerc: "100% of the tenant and all connected workloads",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "AC-2(1) / AC-6(1) / CP-2", Impact: "Automated account management, least privilege for authorized access, and contingency planning controls are all absent for the most privileged accounts."},
			{Framework: "ISO 27001:2022", Control: "A.5.15 / A.5.16 / A.5.30", Impact: "Access control, identity management, and ICT readiness for business continuity are not applied to emergency access scenarios."},
			{Framework: "SOC 2", Control: "CC6.1 / CC6.3 / CC9.1", Impact: "Logical access security, role-based access, and risk mitigation controls fail when emergency recovery is impossible."},
		},
		MinimalFixSet: []string{"zt_id_012", "zt_id_021"},
		PriorityFix: "Provision at least two break-glass accounts with standing Global Administrator role, physical FIDO2 keys stored in separate secure locations, excluded from all Conditional Access policies except a monitoring-only policy. Require PIM approval by a second administrator for Global Administrator activation.",
		BreakingNote: "Enabling PIM approval workflows will slow down legitimate emergency operations. Ensure break-glass accounts are provisioned and tested BEFORE enabling approval requirements. Monitor break-glass sign-in with a dedicated alert rule.",
		MITRETechnique:    "T1078.004 / T1531 / T1484.002",
		MITRETactic:       "Privilege Escalation / Impact / Defense Evasion",
		KillChainPhase:    "Privilege Escalation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-023: Conditional access bypass to identity harvest
// ---------------------------------------------------------------------------

func buildChain023(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_013", "zt_id_018", "zt_id_023")
	triggers := collectFindingIDs(findings, "zt_id_013", "zt_id_018", "zt_id_023")

	return &models.AttackChain{
		ID:                 "CHAIN-023",
		Title:              "Conditional access bypass to identity harvest",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Conditional Access policies do not define named/trusted locations, no sign-in risk policy is configured, and MFA registration is not enforced for new or existing users. " +
			"This trifecta means an attacker who obtains a valid password - from a breach dump, spray, or social engineering - can authenticate from any IP address on Earth without triggering any risk-based evaluation. " +
			"Because MFA registration was never enforced, the target account likely has no second factor at all, or the attacker can register their own MFA method on first sign-in. " +
			"The attacker then harvests the directory: user lists, group memberships, application registrations, and service principal secrets - building a map for deeper compromise.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Obtain a valid user password from a credential breach database or targeted phishing.",
				Technical: "Credential stuffing against login.microsoftonline.com; no named locations means there is no IP-based block or grant control in Conditional Access.",
				Technique: "T1110.004",
				EnabledBy: "zt_id_013",
				Gain:      "Valid username/password pair for an Entra ID user.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Sign in from an anonymous VPN or Tor exit node without triggering any risk detection.",
				Technical: "No sign-in risk policy means Identity Protection does not evaluate atypical travel, anonymous IP, or impossible travel signals; sign-in proceeds as normal.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_018",
				Gain:      "Authenticated session from an untrusted location with no additional challenge.",
			},
			{
				Number:    3,
				Actor:     "Attacker with authenticated session",
				Action:    "Register their own MFA method since the account has none, or bypass MFA entirely.",
				Technical: "MFA registration policy not enforced via Conditional Access or Identity Protection; user account has no registered authentication methods. Attacker registers a phone number or authenticator app.",
				Technique: "T1556.006",
				EnabledBy: "zt_id_023",
				Gain:      "Attacker now owns the MFA registration for the account - persistence through MFA.",
			},
			{
				Number:    4,
				Actor:     "Attacker with persistent access",
				Action:    "Enumerate the Entra ID directory: users, groups, roles, applications, and service principals.",
				Technical: "Microsoft Graph API calls (GET /users, /groups, /applications, /servicePrincipals) with default directory reader permissions available to all authenticated users.",
				Technique: "T1087.004",
				EnabledBy: "zt_id_018",
				Gain:      "Complete directory map including group memberships, role assignments, and application secrets metadata.",
			},
			{
				Number:    5,
				Actor:     "Attacker with directory knowledge",
				Action:    "Identify high-value targets and repeat the credential attack against privileged users.",
				Technical: "Cross-reference the harvested user list with role assignments to find Global Administrators, Application Administrators, and Privileged Role Administrators without MFA.",
				Technique: "T1589.001",
				EnabledBy: "zt_id_023",
				Gain:      "Targeted attack list for privilege escalation across the tenant.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any valid user credential from a breach database or phishing.",
			LateralMovement:    "Directory enumeration → targeted credential attack on privileged users → tenant-wide access.",
			MaxPrivilege:       "Initially standard user; rapidly escalates to whatever the weakest privileged account allows.",
			DataAtRisk:         []string{"Full Entra ID directory contents", "Email and OneDrive of compromised users", "Application secrets metadata", "Group membership and role assignment data"},
			ServicesAtRisk:     []string{"Entra ID", "Microsoft Graph", "Exchange Online", "SharePoint Online", "Any application relying on Entra ID for authentication"},
			EstimatedScopePerc: "All identities in the tenant are exposed to enumeration; compromised scope depends on password reuse",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "IA-2(1) / IA-2(2) / AC-7", Impact: "Multi-factor authentication for privileged and non-privileged accounts and unsuccessful login attempt handling are not implemented."},
			{Framework: "PCI DSS 4.0", Control: "8.3 / 8.4", Impact: "Strong authentication and multi-factor authentication requirements are not met for any user population."},
			{Framework: "ISO 27001:2022", Control: "A.8.2 / A.8.5", Impact: "Privileged access rights and secure authentication controls are absent across the identity plane."},
		},
		MinimalFixSet: []string{"zt_id_018", "zt_id_023"},
		PriorityFix: "Enable sign-in risk policy at medium-and-above risk requiring MFA or block. Enforce MFA registration for all users via Conditional Access. Define named locations for corporate IP ranges and apply location-based grant controls.",
		BreakingNote: "Enforcing MFA registration will force every user to register on next sign-in, which may cause a support surge. Communicate in advance and provide self-service registration instructions. Sign-in risk policy may block legitimate users on VPNs or traveling - tune the named locations first.",
		MITRETechnique:    "T1110.004 / T1078.004 / T1556.006 / T1087.004",
		MITRETactic:       "Credential Access / Initial Access / Persistence / Discovery",
		KillChainPhase:    "Reconnaissance",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-024: Cross-tenant trust abuse to data access
// ---------------------------------------------------------------------------

func buildChain024(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_017", "zt_id_016", "zt_data_011")
	triggers := collectFindingIDs(findings, "zt_id_017", "zt_id_016", "zt_data_011")

	return &models.AttackChain{
		ID:                 "CHAIN-024",
		Title:              "Cross-tenant trust abuse to data access",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Cross-tenant access settings use the default permissive configuration that trusts all external tenants, guest users are granted excessive directory permissions beyond the restricted default, " +
			"and a Cosmos DB account is exposed with a public endpoint. An attacker from a foreign tenant receives or socially engineers a guest invitation. " +
			"Because cross-tenant trust is default, the guest satisfies MFA requirements using their home tenant's MFA - the resource tenant never challenges them independently. " +
			"The overpermissioned guest role grants directory read access and group membership that includes a role with Cosmos DB data plane access. " +
			"The attacker reads production data from the publicly accessible Cosmos DB endpoint using the inherited credentials.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker in a foreign tenant",
				Action:    "Accept or socially engineer a guest invitation to the target tenant.",
				Technical: "B2B invitation via email or direct link; default cross-tenant access settings allow inbound collaboration from all external tenants without restriction.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_017",
				Gain:      "Guest user object in the target tenant.",
			},
			{
				Number:    2,
				Actor:     "Guest user",
				Action:    "Satisfy any Conditional Access MFA requirement using home-tenant MFA claim passthrough.",
				Technical: "Cross-tenant trust settings accept MFA claims from the guest's home tenant (inbound trust redeemMfa=true by default); the resource tenant never issues its own MFA challenge.",
				Technique: "T1556.006",
				EnabledBy: "zt_id_017",
				Gain:      "Full authenticated session in the resource tenant with MFA satisfied externally.",
			},
			{
				Number:    3,
				Actor:     "Guest user with session",
				Action:    "Enumerate directory objects, group memberships, and application assignments.",
				Technical: "Guest user permissions are set beyond the 'most restrictive' default; the guest can read all user profiles, group memberships, and enumerate applications via Microsoft Graph.",
				Technique: "T1087.004",
				EnabledBy: "zt_id_016",
				Gain:      "Full directory enumeration and discovery of data-plane role assignments.",
			},
			{
				Number:    4,
				Actor:     "Guest user with directory knowledge",
				Action:    "Identify and join or leverage group memberships that grant Cosmos DB data plane access.",
				Technical: "Guest is already a member of or can request membership in a security group with Cosmos DB Data Reader or Data Contributor RBAC role assignment.",
				Technique: "T1069.003",
				EnabledBy: "zt_id_016",
				Gain:      "Cosmos DB data plane credentials via inherited RBAC role.",
			},
			{
				Number:    5,
				Actor:     "Guest user with data plane access",
				Action:    "Connect to the public Cosmos DB endpoint and exfiltrate production data.",
				Technical: "Cosmos DB has publicNetworkAccess=Enabled and no IP firewall rules; data plane operations via REST API or SDK using the inherited RBAC token.",
				Technique: "T1530",
				EnabledBy: "zt_data_011",
				Gain:      "Full read access to production data in Cosmos DB containers.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Guest invitation from any external tenant.",
			LateralMovement:    "Guest session → directory enumeration → group-based RBAC inheritance → Cosmos DB data plane.",
			MaxPrivilege:       "Cosmos DB Data Contributor (read/write on all containers) plus full directory read.",
			DataAtRisk:         []string{"All Cosmos DB containers and documents", "Directory user and group data", "Application registration metadata"},
			ServicesAtRisk:     []string{"Azure Cosmos DB", "Entra ID directory", "Any service granting access via group membership"},
			EstimatedScopePerc: "Cosmos DB data + directory metadata",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "AC-17 / IA-8", Impact: "Remote access and identification/authentication of non-organizational users do not enforce independent verification."},
			{Framework: "ISO 27001:2022", Control: "A.5.19 / A.5.20", Impact: "Information security in supplier relationships and ICT supply chain controls are not applied to cross-tenant trust."},
			{Framework: "PCI DSS 4.0", Control: "7.2 / 7.3", Impact: "Access control systems and access management processes do not restrict external guest access to cardholder data environments."},
		},
		MinimalFixSet: []string{"zt_id_017", "zt_data_011"},
		PriorityFix: "Restrict cross-tenant access settings to named partner tenants only and disable automatic MFA trust. Restrict guest user permissions to the 'most restrictive' setting. Disable Cosmos DB public network access and enforce private endpoints.",
		BreakingNote: "Restricting cross-tenant trust will break existing B2B collaboration with partners not explicitly allowlisted. Guest permission restriction may break applications that rely on guest directory enumeration. Disabling Cosmos DB public access requires all clients to use private endpoints.",
		MITRETechnique:    "T1078.004 / T1087.004 / T1530",
		MITRETactic:       "Initial Access / Discovery / Collection",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-025: AKS cluster full compromise
// ---------------------------------------------------------------------------

func buildChain025(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_014", "zt_wl_015", "zt_wl_016")
	triggers := collectFindingIDs(findings, "zt_wl_014", "zt_wl_015", "zt_wl_016")

	return &models.AttackChain{
		ID:                 "CHAIN-025",
		Title:              "AKS cluster full compromise",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An AKS cluster has no Kubernetes network policies enforced, uses legacy Kubernetes RBAC instead of Azure RBAC for Kubernetes authorization, and has no pod security standards applied. " +
			"An attacker who gains code execution in any pod - through a vulnerable application, SSRF, or compromised dependency - can reach every other pod and service in the cluster because no network segmentation exists. " +
			"The attacker then escalates to cluster-admin through the legacy Kubernetes RBAC system, which often has overly permissive default ClusterRoleBindings. " +
			"With cluster-admin, the attacker deploys privileged pods with hostPath mounts to escape to the node, access the kubelet identity, and pivot to Azure Resource Manager.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker with pod-level access",
				Action:    "Perform network reconnaissance across all namespaces from within a compromised pod.",
				Technical: "No Kubernetes NetworkPolicy objects exist; default behavior is allow-all ingress and egress across all namespaces. Pod can reach kube-dns, kube-apiserver, and all service ClusterIPs.",
				Technique: "T1046",
				EnabledBy: "zt_wl_014",
				Gain:      "Full network map of all services, pods, and endpoints in the cluster.",
			},
			{
				Number:    2,
				Actor:     "Attacker in compromised pod",
				Action:    "Reach and exploit adjacent pods hosting different microservices.",
				Technical: "No east-west traffic restrictions; attacker connects to database pods, cache instances, and internal APIs directly via cluster networking.",
				Technique: "T1021",
				EnabledBy: "zt_wl_014",
				Gain:      "Access to internal services that should only be reachable by specific workloads.",
			},
			{
				Number:    3,
				Actor:     "Attacker with lateral movement",
				Action:    "Escalate to cluster-admin by exploiting legacy Kubernetes RBAC misconfigurations.",
				Technical: "Azure RBAC for Kubernetes is not enabled; local Kubernetes RBAC has default ClusterRoleBindings granting excessive permissions to service accounts. kubectl auth can-i --list reveals cluster-admin equivalent permissions.",
				Technique: "T1078.001",
				EnabledBy: "zt_wl_015",
				Gain:      "cluster-admin role binding - full control over all Kubernetes resources.",
			},
			{
				Number:    4,
				Actor:     "Attacker with cluster-admin",
				Action:    "Deploy a privileged pod with hostPath mount to escape the container boundary.",
				Technical: "No pod security admission (no PodSecurity standards or OPA/Gatekeeper policies); attacker creates a pod with securityContext.privileged=true and hostPath=/ to mount the node filesystem.",
				Technique: "T1611",
				EnabledBy: "zt_wl_016",
				Gain:      "Root access on the underlying AKS node.",
			},
			{
				Number:    5,
				Actor:     "Attacker on AKS node",
				Action:    "Steal the kubelet managed identity token from IMDS and pivot to Azure Resource Manager.",
				Technical: "curl http://169.254.169.254/metadata/identity/oauth2/token on the node returns an ARM token for the kubelet identity; this identity typically has Contributor on the MC_ resource group.",
				Technique: "T1552.005",
				EnabledBy: "zt_wl_016",
				Gain:      "Azure ARM access with the kubelet managed identity - control over the AKS infrastructure resource group.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Code execution in any pod (vulnerable app, supply chain, SSRF).",
			LateralMovement:    "Compromised pod → all cluster pods → cluster-admin → node escape → Azure ARM.",
			MaxPrivilege:       "cluster-admin + kubelet managed identity (typically Contributor on the MC_ resource group).",
			DataAtRisk:         []string{"All data in all cluster workloads", "Kubernetes secrets", "Managed identity tokens", "ConfigMaps with credentials", "Persistent volumes"},
			ServicesAtRisk:     []string{"AKS cluster", "All microservices", "Azure Resource Manager (MC_ resource group)", "Any Azure service the kubelet identity can reach"},
			EstimatedScopePerc: "Entire AKS cluster + its infrastructure resource group",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "AC-4 / SC-7 / AC-6", Impact: "Information flow enforcement, boundary protection, and least privilege are absent in the Kubernetes layer."},
			{Framework: "PCI DSS 4.0", Control: "1.3 / 2.2 / 7.1", Impact: "Network access controls, secure configurations, and access restriction to system components are not applied to the container orchestration platform."},
			{Framework: "ISO 27001:2022", Control: "A.8.22 / A.8.24 / A.8.3", Impact: "Segregation in networks, use of cryptography, and information access restriction are not implemented for container workloads."},
		},
		MinimalFixSet: []string{"zt_wl_014", "zt_wl_016"},
		PriorityFix: "Deploy default-deny NetworkPolicy in every namespace. Enable Azure RBAC for Kubernetes authorization. Enforce PodSecurity admission at the 'restricted' level or deploy OPA Gatekeeper with a baseline constraint library.",
		BreakingNote: "Default-deny NetworkPolicy will break any pod-to-pod communication not explicitly allowed - roll out per namespace with thorough testing. Switching from Kubernetes RBAC to Azure RBAC requires re-creating role bindings as Azure role assignments. PodSecurity 'restricted' will reject workloads needing privileged features.",
		MITRETechnique:    "T1046 / T1078.001 / T1611 / T1552.005",
		MITRETactic:       "Discovery / Privilege Escalation / Credential Access",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-026: Container registry takeover to supply chain poisoning
// ---------------------------------------------------------------------------

func buildChain026(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_012", "zt_wl_013", "zt_wl_021")
	triggers := collectFindingIDs(findings, "zt_wl_012", "zt_wl_013", "zt_wl_021")

	return &models.AttackChain{
		ID:                 "CHAIN-026",
		Title:              "Container registry takeover to supply chain poisoning",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Azure Container Registry has the admin account enabled, the registry is publicly accessible on the internet, and Microsoft Defender for Containers is not enabled. " +
			"The admin credential is a static username/password pair that is frequently embedded in CI/CD pipelines, developer machines, and configuration files. " +
			"An attacker who discovers this credential - through a leaked pipeline definition, a compromised developer workstation, or brute-force against the public endpoint - gains full push/pull access to all repositories. " +
			"The attacker overwrites production image tags with backdoored variants. Without Defender for Containers, there is no runtime vulnerability scanning, no image integrity verification, and no behavioral detection when the malicious images execute in downstream clusters.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Discover the ACR admin credential from a leaked CI/CD pipeline, repository secret, or developer environment.",
				Technical: "ACR admin account is enabled (adminUserEnabled=true); the credential is a static password that does not rotate automatically and is often stored in plaintext in build definitions.",
				Technique: "T1552.001",
				EnabledBy: "zt_wl_012",
				Gain:      "ACR admin username and password.",
			},
			{
				Number:    2,
				Actor:     "Attacker with admin credential",
				Action:    "Authenticate to the public ACR endpoint and enumerate all repositories and tags.",
				Technical: "ACR public network access is enabled with no IP firewall rules; docker login <registry>.azurecr.io succeeds from any IP. Catalog API lists all repositories.",
				Technique: "T1595.002",
				EnabledBy: "zt_wl_013",
				Gain:      "Full inventory of all container images and tags in the registry.",
			},
			{
				Number:    3,
				Actor:     "Attacker with registry access",
				Action:    "Pull a production image, inject a backdoor, and push it back to the same tag.",
				Technical: "docker pull, modify Dockerfile to add a reverse shell or crypto miner layer, docker push to overwrite the existing tag (e.g., :latest or :v2.1.0). No content trust or image signing is enforced.",
				Technique: "T1195.002",
				EnabledBy: "zt_wl_012",
				Gain:      "Malicious image sitting at a trusted production tag.",
			},
			{
				Number:    4,
				Actor:     "Downstream AKS or App Service",
				Action:    "Pull the tainted image on next deployment or pod restart.",
				Technical: "imagePullPolicy: Always or a rolling deployment triggers a pull of the compromised tag; the workload starts executing attacker code.",
				Technique: "T1059",
				EnabledBy: "zt_wl_013",
				Gain:      "Attacker code executing inside production workloads.",
			},
			{
				Number:    5,
				Actor:     "Malicious container in production",
				Action:    "Operate undetected because no runtime security monitoring exists.",
				Technical: "Defender for Containers is not enabled; no runtime behavioral analysis, no vulnerability assessment on running images, no anomalous process detection.",
				Technique: "T1562.001",
				EnabledBy: "zt_wl_021",
				Gain:      "Persistent undetected supply chain compromise across all workloads pulling from the registry.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Leaked or brute-forced ACR admin credential over the public endpoint.",
			LateralMovement:    "Poisoned image → every workload pulling that tag → all environments (dev, staging, production).",
			MaxPrivilege:       "Full registry write access + code execution in every consuming workload.",
			DataAtRisk:         []string{"All data accessible to workloads pulling from ACR", "Application secrets in environment variables", "Managed identity tokens in running containers", "Customer data processed by affected services"},
			ServicesAtRisk:     []string{"Azure Container Registry", "AKS clusters", "App Service containers", "Azure Container Instances", "Any CI/CD pipeline consuming images"},
			EstimatedScopePerc: "All workloads pulling from the compromised registry",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "SA-12 / SR-3 / SR-11", Impact: "Supply chain protection, provenance tracking, and component authenticity controls are absent for container artifacts."},
			{Framework: "PCI DSS 4.0", Control: "6.3 / 6.5 / 11.6", Impact: "Security patches, change management, and tamper detection mechanisms are not applied to container images."},
			{Framework: "SOC 2", Control: "CC8.1 / CC7.1 / CC7.2", Impact: "Change management, infrastructure monitoring, and security event detection do not cover the container supply chain."},
		},
		MinimalFixSet: []string{"zt_wl_012", "zt_wl_021"},
		PriorityFix: "Disable the ACR admin account and switch all authentication to managed identities or service principals with scoped RBAC. Enable Defender for Containers to get runtime protection and image vulnerability scanning. Restrict ACR to private endpoints or IP-restricted access.",
		BreakingNote: "Disabling the admin account will break any CI/CD pipeline, script, or developer workflow that authenticates with the admin credential. Migrate all consumers to managed identity or service principal authentication first. Private endpoint enforcement requires all pulling clients to be on the virtual network.",
		MITRETechnique:    "T1552.001 / T1195.002 / T1562.001",
		MITRETactic:       "Credential Access / Initial Access / Defense Evasion",
		KillChainPhase:    "Delivery",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-027: App Service remote debug to internal pivot
// ---------------------------------------------------------------------------

func buildChain027(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_018", "zt_net_019", "zt_vis_019")
	triggers := collectFindingIDs(findings, "zt_wl_018", "zt_net_019", "zt_vis_019")

	return &models.AttackChain{
		ID:                 "CHAIN-027",
		Title:              "App Service remote debug to internal pivot",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An Azure App Service has remote debugging enabled in production, the delegated subnet hosting the App Service has no Network Security Group attached, and Application Insights is not configured for the application. " +
			"Remote debugging exposes a debug endpoint that grants full process-level access to the running application - memory inspection, code injection, and arbitrary command execution. " +
			"An attacker who discovers or brute-forces the debug port gains a foothold inside the App Service sandbox and, through VNet integration, reaches the internal subnet. " +
			"Because no NSG filters traffic on the subnet, the attacker can scan and connect to any internal resource - databases, caches, other App Services, VMs - without restriction. " +
			"With no Application Insights telemetry, there is no APM-level detection of anomalous requests, unusual response patterns, or unexpected outbound connections.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Discover and attach to the remote debug endpoint on the App Service.",
				Technical: "Remote debugging is enabled (remoteDebuggingEnabled=true); the debug endpoint is accessible and allows attaching a debugger (e.g., Visual Studio Remote Debugger) to the w3wp or dotnet process.",
				Technique: "T1190",
				EnabledBy: "zt_wl_018",
				Gain:      "Full debug-level access to the running application process.",
			},
			{
				Number:    2,
				Actor:     "Attacker with debugger access",
				Action:    "Extract environment variables, connection strings, and managed identity tokens from the process memory.",
				Technical: "Debug session allows inspecting process environment, reading connection strings from appsettings, and calling the local IMDS endpoint for managed identity tokens.",
				Technique: "T1552.005",
				EnabledBy: "zt_wl_018",
				Gain:      "Database connection strings, storage keys, managed identity tokens, and application secrets.",
			},
			{
				Number:    3,
				Actor:     "Attacker with internal credentials",
				Action:    "Scan the VNet-integrated subnet for adjacent resources.",
				Technical: "App Service VNet integration places outbound traffic on the delegated subnet; no NSG restricts egress or east-west traffic. Attacker runs port scans against the subnet CIDR and adjacent subnets.",
				Technique: "T1046",
				EnabledBy: "zt_net_019",
				Gain:      "Network map of all reachable internal resources - databases, caches, VMs, other App Services.",
			},
			{
				Number:    4,
				Actor:     "Attacker with network access",
				Action:    "Connect to internal databases and services using the stolen credentials.",
				Technical: "SQL Server, Redis, Cosmos DB, or other backends are reachable on the subnet with no NSG filtering; stolen connection strings provide authentication.",
				Technique: "T1021",
				EnabledBy: "zt_net_019",
				Gain:      "Direct access to backend data stores and internal APIs.",
			},
			{
				Number:    5,
				Actor:     "Attacker operating internally",
				Action:    "Exfiltrate data without triggering any application-level detection.",
				Technical: "No Application Insights means no request tracing, no dependency tracking, no anomaly detection on response times or error rates. The attack is invisible at the APM layer.",
				Technique: "T1041",
				EnabledBy: "zt_vis_019",
				Gain:      "Sustained data exfiltration with no application monitoring to raise alerts.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Remote debug endpoint on a production App Service.",
			LateralMovement:    "App Service sandbox → VNet-integrated subnet → all reachable internal resources.",
			MaxPrivilege:       "Application managed identity + all credentials in the process environment.",
			DataAtRisk:         []string{"Application data", "Backend database contents", "Cache contents (Redis)", "Managed identity scope", "Connection strings and secrets"},
			ServicesAtRisk:     []string{"App Service", "SQL Database", "Redis Cache", "Cosmos DB", "Any VNet-connected service on unprotected subnets"},
			EstimatedScopePerc: "The App Service and all backend services it can reach through VNet integration",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "CM-7 / SC-7 / SI-4", Impact: "Least functionality, boundary protection, and system monitoring controls are violated by an open debug endpoint with no network segmentation or application monitoring."},
			{Framework: "PCI DSS 4.0", Control: "2.2 / 1.3 / 10.4", Impact: "Secure configuration, network access controls, and audit log review are not applied to the application environment."},
			{Framework: "ISO 27001:2022", Control: "A.8.9 / A.8.22 / A.8.16", Impact: "Configuration management, network segregation, and monitoring activities are absent for the application workload."},
		},
		MinimalFixSet: []string{"zt_wl_018", "zt_net_019"},
		PriorityFix: "Disable remote debugging on all production App Services immediately. Attach NSGs to all delegated subnets with default-deny inbound and restricted outbound rules. Enable Application Insights with smart detection alerts for anomalous behavior.",
		BreakingNote: "Disabling remote debugging may affect developer troubleshooting workflows - provide alternative diagnostic tools (Kudu console, snapshot debugger with proper RBAC). NSG enforcement on delegated subnets may block legitimate VNet-integrated traffic if rules are too restrictive - test with logging-only NSGs first.",
		MITRETechnique:    "T1190 / T1552.005 / T1046 / T1041",
		MITRETactic:       "Initial Access / Credential Access / Discovery / Exfiltration",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-028: Key Vault silent breach and purge
// ---------------------------------------------------------------------------

func buildChain028(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_014", "zt_vis_014", "zt_id_024")
	triggers := collectFindingIDs(findings, "zt_data_014", "zt_vis_014", "zt_id_024")

	return &models.AttackChain{
		ID:                 "CHAIN-028",
		Title:              "Key Vault silent breach and purge",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "A Key Vault has purge protection disabled, its diagnostic logging is not configured, and stale service principal credentials exist in the tenant that still have Key Vault access policies or RBAC roles. " +
			"An attacker discovers an old, forgotten service principal credential - from a decommissioned application, a developer's notes, or a leaked CI/CD configuration. " +
			"The stale credential still authenticates successfully and retains its Key Vault access. The attacker reads all secrets, keys, and certificates, then soft-deletes and immediately purges the vault. " +
			"Because diagnostic logging was never enabled, there is no audit trail of who accessed the vault or when the purge occurred. " +
			"The combination of no purge protection, no logging, and stale credentials creates an unrecoverable, uninvestigable cryptographic material loss.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Discover a stale service principal credential that was never rotated or decommissioned.",
				Technical: "Service principal has passwordCredentials with endDateTime far in the future or already expired but still functional (credential not removed, just expired); found in old repo, wiki, or config file.",
				Technique: "T1552.001",
				EnabledBy: "zt_id_024",
				Gain:      "Valid service principal credential with Key Vault permissions.",
			},
			{
				Number:    2,
				Actor:     "Attacker with SP credential",
				Action:    "Authenticate as the service principal and enumerate accessible Key Vault resources.",
				Technical: "az login --service-principal; then az keyvault list to find vaults where the SP has access policies or RBAC data-plane roles.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_024",
				Gain:      "List of Key Vaults accessible to the compromised service principal.",
			},
			{
				Number:    3,
				Actor:     "Attacker with vault access",
				Action:    "Read all secrets, keys, and certificates from the vault.",
				Technical: "az keyvault secret list / az keyvault secret show for each secret; same for keys and certificates. All cryptographic material and connection strings exfiltrated.",
				Technique: "T1555",
				EnabledBy: "zt_vis_014",
				Gain:      "Complete copy of all secrets, keys, and certificates - database passwords, API keys, TLS certificates, encryption keys.",
			},
			{
				Number:    4,
				Actor:     "Attacker covering tracks",
				Action:    "Soft-delete the vault and immediately purge it to destroy evidence.",
				Technical: "az keyvault delete followed by az keyvault purge; purge protection is disabled (enablePurgeProtection=false), so purge succeeds immediately instead of enforcing the retention period.",
				Technique: "T1485",
				EnabledBy: "zt_data_014",
				Gain:      "Vault and all its contents permanently destroyed with no recovery possible.",
			},
			{
				Number:    5,
				Actor:     "Defenders responding",
				Action:    "Discover the vault is gone and find no diagnostic logs to investigate.",
				Technical: "No diagnostic settings were configured on the vault (diagnosticSettings is empty); AuditEvent logs were never sent to Log Analytics, Storage, or Event Hub. The Azure Activity Log shows the delete but not the data-plane reads.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_014",
				Gain:      "Investigation is impossible - no record of what was read, by whom, or when. Incident response is blind.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Stale service principal credential with Key Vault access.",
			LateralMovement:    "Stolen secrets enable lateral movement to every service whose credentials were in the vault.",
			MaxPrivilege:       "Full Key Vault data plane access + ability to purge.",
			DataAtRisk:         []string{"All secrets in the vault", "All encryption keys", "All TLS certificates", "All systems whose credentials were stored in the vault"},
			ServicesAtRisk:     []string{"Azure Key Vault", "Every service whose secrets were in the vault (databases, APIs, storage accounts, third-party services)", "Encryption-dependent workloads"},
			EstimatedScopePerc: "The vault contents + every downstream system authenticated by vault secrets",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "SC-12 / AU-3 / AU-9", Impact: "Cryptographic key establishment and management, audit record content, and protection of audit information are all compromised when keys are purged and no logs exist."},
			{Framework: "PCI DSS 4.0", Control: "3.6 / 10.2 / 10.5", Impact: "Cryptographic key management procedures, audit log implementation, and secure retention of audit trails are violated."},
			{Framework: "ISO 27001:2022", Control: "A.8.24 / A.8.15 / A.8.10", Impact: "Use of cryptography, logging, and information deletion controls are absent for the most sensitive cryptographic material."},
		},
		MinimalFixSet: []string{"zt_data_014", "zt_vis_014"},
		PriorityFix: "Enable purge protection on all Key Vaults (this is irreversible once enabled). Configure diagnostic settings to send AuditEvent logs to a Log Analytics workspace with a retention period of at least 90 days. Audit and remove all stale service principal credentials.",
		BreakingNote: "Purge protection enforces a mandatory retention period (7-90 days) during which soft-deleted vaults cannot be purged. This is by design but may surprise teams accustomed to cleaning up test vaults. Diagnostic logging has an ingestion cost proportional to vault activity.",
		MITRETechnique:    "T1552.001 / T1555 / T1485 / T1562.008",
		MITRETactic:       "Credential Access / Impact / Defense Evasion",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-029: SQL database invisible exfiltration
// ---------------------------------------------------------------------------

func buildChain029(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_012", "zt_vis_015", "zt_data_015")
	triggers := collectFindingIDs(findings, "zt_data_012", "zt_vis_015", "zt_data_015")

	return &models.AttackChain{
		ID:                 "CHAIN-029",
		Title:              "SQL database invisible exfiltration",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Azure SQL auditing is not enabled, the audit log retention period is set below 90 days (or effectively zero), and Transparent Data Encryption uses a service-managed key instead of a customer-managed key. " +
			"An attacker who gains access to the SQL database through a compromised connection string, SQL injection, or credential reuse can execute arbitrary queries and exfiltrate the entire database. " +
			"Because auditing is disabled or has minimal retention, there is no record of the queries executed, the data accessed, or the volume exfiltrated. " +
			"The service-managed TDE key means the customer has no ability to revoke the encryption key to render the stolen data unreadable - Microsoft manages the key lifecycle and the attacker's copy is decrypted at rest.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Gain access to the SQL database through a compromised connection string or SQL injection vulnerability.",
				Technical: "Connection string found in a public repository, application configuration leak, or SQL injection in a web application frontend. Authentication succeeds with SQL authentication or a stolen AAD token.",
				Technique: "T1190",
				EnabledBy: "zt_data_012",
				Gain:      "Authenticated session to the Azure SQL database.",
			},
			{
				Number:    2,
				Actor:     "Attacker with database access",
				Action:    "Enumerate database schemas, tables, and row counts to identify high-value data.",
				Technical: "SELECT * FROM INFORMATION_SCHEMA.TABLES; SELECT COUNT(*) FROM each table; identify PII, financial, and sensitive business data.",
				Technique: "T1505.001",
				EnabledBy: "zt_data_012",
				Gain:      "Complete schema map and data inventory of the database.",
			},
			{
				Number:    3,
				Actor:     "Attacker with schema knowledge",
				Action:    "Bulk export sensitive data using SELECT INTO OUTFILE equivalents or BCP-style export via the compromised session.",
				Technical: "Data exfiltrated via application-layer queries, OPENROWSET to an external data source, or row-by-row extraction through the application; no audit log captures the queries.",
				Technique: "T1048",
				EnabledBy: "zt_vis_015",
				Gain:      "Complete copy of sensitive database contents exfiltrated to attacker-controlled infrastructure.",
			},
			{
				Number:    4,
				Actor:     "Attacker with exfiltrated data",
				Action:    "Retain the data in a decrypted, usable form because TDE with service-managed keys provides no customer-side revocation.",
				Technical: "TDE encrypts data at rest with a service-managed key; once data is read through the SQL engine, it is decrypted. The customer cannot rotate or revoke the key to render stolen data unreadable.",
				Technique: "T1530",
				EnabledBy: "zt_data_015",
				Gain:      "Permanent possession of decrypted production data with no mechanism for the victim to invalidate it.",
			},
			{
				Number:    5,
				Actor:     "Defenders responding to breach notification",
				Action:    "Attempt forensic investigation and find no meaningful audit trail.",
				Technical: "SQL auditing was disabled or retention was below 90 days; no record of which queries were executed, what data was accessed, or the timeframe of the breach. Incident response and regulatory notification lack required details.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_015",
				Gain:      "Defenders cannot scope the breach, identify affected records, or meet regulatory notification requirements with specificity.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Compromised SQL connection string or SQL injection.",
			LateralMovement:    "Database access → full schema enumeration → bulk data export.",
			MaxPrivilege:       "Database owner or whatever role the compromised credential holds.",
			DataAtRisk:         []string{"All data in the SQL database", "PII and financial records", "Business-critical data", "Application metadata and configuration stored in the database"},
			ServicesAtRisk:     []string{"Azure SQL Database", "Applications dependent on the database", "Downstream analytics and reporting systems"},
			EstimatedScopePerc: "All data in the affected database(s)",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "10.2 / 10.5 / 3.5", Impact: "Audit logging, secure log retention, and rendering stored account data unrecoverable are not met."},
			{Framework: "NIST 800-53", Control: "AU-2 / AU-11 / SC-28", Impact: "Auditable events, audit record retention, and protection of information at rest controls are absent for the database."},
			{Framework: "ISO 27001:2022", Control: "A.8.15 / A.8.10 / A.8.24", Impact: "Logging, information deletion, and use of cryptography controls are not applied to protect database audit trails and encryption keys."},
		},
		MinimalFixSet: []string{"zt_data_012", "zt_vis_015"},
		PriorityFix: "Enable SQL auditing on all databases and servers with a retention period of at least 90 days, sending logs to a Log Analytics workspace. Migrate TDE to customer-managed keys in Azure Key Vault to enable key revocation in breach scenarios.",
		BreakingNote: "Enabling auditing has a minor performance impact and storage cost. Migrating to customer-managed TDE keys introduces a dependency on Key Vault availability - if the key is inaccessible, the database becomes inaccessible. Ensure Key Vault has high availability and soft-delete/purge protection.",
		MITRETechnique:    "T1190 / T1048 / T1562.008",
		MITRETactic:       "Initial Access / Exfiltration / Defense Evasion",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-030: Storage account ransomware with no recovery
// ---------------------------------------------------------------------------

func buildChain030(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_013", "zt_data_016", "zt_data_017")
	triggers := collectFindingIDs(findings, "zt_data_013", "zt_data_016", "zt_data_017")

	return &models.AttackChain{
		ID:                 "CHAIN-030",
		Title:              "Storage account ransomware with no recovery",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Blob soft delete is not enabled on the storage account, blob versioning is disabled, and no Azure Backup vault protects the storage data. " +
			"This combination removes every recovery mechanism for blob data. An attacker who gains access to the storage account - through a leaked account key, a compromised SAS token, or an overprivileged managed identity - " +
			"can overwrite or delete every blob in every container. Without soft delete, deleted blobs are immediately gone. Without versioning, overwritten blobs lose their previous content permanently. " +
			"Without Azure Backup, there is no point-in-time restore capability. The attacker can execute a complete ransomware scenario: encrypt or delete all data and demand payment, " +
			"knowing that the victim has no technical path to recovery.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Obtain storage account credentials through a leaked account key, overly permissive SAS token, or compromised identity.",
				Technical: "Storage account keys are static and grant full control; SAS tokens may have overly broad permissions (sp=rwdlac) and long expiry dates; managed identities with Storage Blob Data Contributor role provide full data-plane access.",
				Technique: "T1528",
				EnabledBy: "zt_data_013",
				Gain:      "Full data-plane access to the storage account.",
			},
			{
				Number:    2,
				Actor:     "Attacker with storage access",
				Action:    "Enumerate all containers and blobs to assess the scope of the target.",
				Technical: "List containers API and list blobs API; identify containers with business-critical data, backups, application state, and media files.",
				Technique: "T1619",
				EnabledBy: "zt_data_013",
				Gain:      "Complete inventory of all blob data in the storage account.",
			},
			{
				Number:    3,
				Actor:     "Attacker with inventory",
				Action:    "Overwrite all blobs with encrypted versions or random data.",
				Technical: "PUT Blob to overwrite each blob with attacker-encrypted content; because versioning is disabled (isVersioningEnabled=false), the previous blob content is permanently lost on overwrite.",
				Technique: "T1486",
				EnabledBy: "zt_data_016",
				Gain:      "All original blob data is permanently destroyed and replaced with unusable content.",
			},
			{
				Number:    4,
				Actor:     "Attacker completing ransomware",
				Action:    "Delete any remaining blobs and containers that were not overwritten.",
				Technical: "DELETE Blob and DELETE Container APIs; soft delete is not enabled (deleteRetentionPolicy.enabled=false), so deleted blobs are immediately and permanently removed.",
				Technique: "T1485",
				EnabledBy: "zt_data_013",
				Gain:      "Complete destruction of all blob data with no soft-delete recovery window.",
			},
			{
				Number:    5,
				Actor:     "Defenders attempting recovery",
				Action:    "Discover that no backup or restore mechanism exists for the storage account.",
				Technical: "No Azure Backup vault has a backup policy targeting this storage account; point-in-time restore requires both versioning and change feed, which are disabled; no third-party backup solution is configured.",
				Technique: "T1490",
				EnabledBy: "zt_data_017",
				Gain:      "Data is unrecoverable - the attacker's ransomware demand is the only option on the table.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Leaked storage account key, compromised SAS token, or overprivileged identity.",
			LateralMovement:    "Not required - storage account access is sufficient for complete data destruction.",
			MaxPrivilege:       "Storage account key (full control) or Storage Blob Data Contributor.",
			DataAtRisk:         []string{"All blobs in all containers", "Application data", "Media files", "Exported reports", "Backup data stored in blob storage"},
			ServicesAtRisk:     []string{"Azure Storage Account", "All applications reading from the storage account", "Analytics pipelines consuming blob data", "Static websites hosted on the storage account"},
			EstimatedScopePerc: "100% of data in the affected storage account(s)",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "CP-9 / CP-10 / SI-12", Impact: "Information system backup, system recovery and reconstitution, and information management and retention controls are absent for blob storage."},
			{Framework: "PCI DSS 4.0", Control: "9.4 / 12.10", Impact: "Media protection and incident response plan requirements are unmet when no backup or recovery path exists for stored data."},
			{Framework: "ISO 27001:2022", Control: "A.8.13 / A.8.14 / A.5.30", Impact: "Information backup, redundancy of information processing, and ICT readiness for business continuity are not implemented for critical storage."},
		},
		MinimalFixSet: []string{"zt_data_013", "zt_data_016"},
		PriorityFix: "Enable blob soft delete with a minimum 14-day retention period. Enable blob versioning to preserve previous versions on overwrite. Configure Azure Backup for blob storage with a retention policy aligned to business requirements.",
		BreakingNote: "Enabling versioning increases storage costs as every overwrite creates a new version. Implement lifecycle management policies to automatically delete old versions after the retention period. Soft delete also increases storage consumption during the retention window.",
		MITRETechnique:    "T1486 / T1485 / T1490",
		MITRETactic:       "Impact",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-031: Network perimeter collapse
// ---------------------------------------------------------------------------

func buildChain031(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_011", "zt_net_019", "zt_net_018")
	triggers := collectFindingIDs(findings, "zt_net_011", "zt_net_019", "zt_net_018")

	return &models.AttackChain{
		ID:                 "CHAIN-031",
		Title:              "Network perimeter collapse",
		Severity:           "HIGH",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "No Azure Firewall or equivalent network virtual appliance provides centralized traffic inspection, multiple subnets have no Network Security Groups attached, and the NSGs that do exist allow all outbound traffic. " +
			"This triple failure collapses the network perimeter into a flat, unmonitored topology. Any attacker who gains access to a single resource on the virtual network - through a compromised VM, " +
			"a vulnerable application, or a stolen credential - can move laterally to every subnet without crossing a security boundary. " +
			"Exfiltration is trivial because outbound traffic flows unrestricted to the internet. There is no centralized logging of network flows, no east-west filtering, and no egress control. " +
			"The environment provides the same network security as a home WiFi router.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker with initial foothold",
				Action:    "Discover that no network segmentation exists between subnets.",
				Technical: "No NSG is attached to the subnet (networkSecurityGroup=null on the subnet resource); all inbound and outbound traffic is allowed by default. ARP/ping sweep reveals all hosts on adjacent subnets.",
				Technique: "T1046",
				EnabledBy: "zt_net_019",
				Gain:      "Full network visibility across all subnets in the virtual network.",
			},
			{
				Number:    2,
				Actor:     "Attacker with network map",
				Action:    "Move laterally to resources on other subnets without any firewall or NSG blocking the connection.",
				Technical: "Direct TCP/UDP connections to databases, management ports (RDP/SSH), internal APIs, and storage endpoints on other subnets; no micro-segmentation exists.",
				Technique: "T1021",
				EnabledBy: "zt_net_019",
				Gain:      "Access to resources across multiple subnets - databases, VMs, internal services.",
			},
			{
				Number:    3,
				Actor:     "Attacker moving laterally",
				Action:    "Confirm that no centralized firewall inspects or logs the lateral movement.",
				Technical: "No Azure Firewall, third-party NVA, or route table forcing traffic through a central inspection point; traffic between subnets goes directly through the Azure fabric with no logging.",
				Technique: "T1562.004",
				EnabledBy: "zt_net_011",
				Gain:      "Complete freedom of movement with no network-layer detection.",
			},
			{
				Number:    4,
				Actor:     "Attacker with lateral access",
				Action:    "Exfiltrate data directly to the internet through unrestricted outbound NSG rules.",
				Technical: "NSGs that exist have outbound rules allowing Destination=* Port=* Protocol=*; there is no Azure Firewall to enforce application-level egress rules or FQDN filtering.",
				Technique: "T1048",
				EnabledBy: "zt_net_018",
				Gain:      "Unrestricted exfiltration path to any internet destination on any port.",
			},
			{
				Number:    5,
				Actor:     "Attacker establishing persistence",
				Action:    "Set up a reverse shell or C2 channel on a high port that blends with legitimate traffic.",
				Technical: "Outbound to any port is allowed; attacker establishes HTTPS-based C2 on port 443 to an attacker-controlled domain. No Azure Firewall TLS inspection or FQDN filtering exists to detect the anomalous destination.",
				Technique: "T1571",
				EnabledBy: "zt_net_018",
				Gain:      "Persistent command-and-control channel that is indistinguishable from legitimate HTTPS traffic at the network layer.",
			},
			{
				Number:    6,
				Actor:     "Defenders investigating",
				Action:    "Find no centralized network flow logs or firewall logs to reconstruct the attack path.",
				Technical: "No Azure Firewall means no firewall diagnostic logs; NSG flow logs may not be enabled on the NSGs that exist, and subnets without NSGs have no flow logging at all. Network forensics is impossible.",
				Technique: "T1562.008",
				EnabledBy: "zt_net_011",
				Gain:      "The attack is invisible at the network layer - no flow records, no firewall logs, no IDS alerts.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any compromised resource on the virtual network.",
			LateralMovement:    "Unrestricted movement across all subnets - the network is flat.",
			MaxPrivilege:       "Network-level access to every resource on every subnet.",
			DataAtRisk:         []string{"All data on all VNet-connected resources", "Database contents", "File shares", "Internal API data", "Management plane credentials exposed on the network"},
			ServicesAtRisk:     []string{"All VMs", "All databases with VNet endpoints", "All internal APIs", "All PaaS services with VNet integration", "Any service reachable from the virtual network"},
			EstimatedScopePerc: "All resources on the virtual network and connected peered networks",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "1.2 / 1.3 / 1.4", Impact: "Network security controls, network access restrictions, and network connections between trusted and untrusted networks are not implemented."},
			{Framework: "NIST 800-53", Control: "SC-7 / AC-4 / AU-12", Impact: "Boundary protection, information flow enforcement, and audit record generation at network boundaries are completely absent."},
			{Framework: "ISO 27001:2022", Control: "A.8.20 / A.8.21 / A.8.22", Impact: "Network security, security of network services, and segregation in networks are not implemented for the Azure virtual network."},
		},
		MinimalFixSet: []string{"zt_net_019", "zt_net_018"},
		PriorityFix: "Attach NSGs with default-deny inbound rules to every subnet. Deploy Azure Firewall (or a third-party NVA) as a centralized egress point with FQDN-based outbound filtering. Update NSG outbound rules to deny direct internet access and force traffic through the firewall via route tables.",
		BreakingNote: "Default-deny NSGs will break any traffic flow not explicitly allowed - deploy in audit mode (NSG flow logs) first to inventory legitimate flows before enforcing. Forcing egress through Azure Firewall requires UDR changes on every subnet and may break services that expect direct internet access (e.g., Azure PaaS management traffic). Use service tags in firewall rules to preserve platform connectivity.",
		MITRETechnique:    "T1046 / T1021 / T1048 / T1562.004",
		MITRETactic:       "Discovery / Lateral Movement / Exfiltration / Defense Evasion",
		KillChainPhase:    "Lateral Movement",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-032: Web App Exploitation with No WAF Protection
// ---------------------------------------------------------------------------

func buildChain032(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_014", "zt_wl_017", "zt_vis_019")
	triggers := collectFindingIDs(findings, "zt_net_014", "zt_wl_017", "zt_vis_019")

	return &models.AttackChain{
		ID:                 "CHAIN-032",
		Title:              "Web App Exploitation with No WAF Protection",
		Severity:           "HIGH",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Application Gateway is deployed without a Web Application Firewall policy, Function Apps or App Services run on outdated runtime stacks with known CVEs, " +
			"and Application Insights is not configured to provide application-level telemetry. An attacker who discovers the publicly-reachable endpoint uses standard " +
			"web exploitation techniques - SQL injection, SSRF, deserialization - against the unpatched runtime. No WAF rule fires because there is no WAF. " +
			"No APM alert triggers because Application Insights is absent. The attacker achieves code execution on the app service plan, harvests environment variables " +
			"containing connection strings and managed identity tokens, and pivots to backend data stores without a single detection event reaching the operations team.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Discover the public FQDN of the App Service or Function App behind the Application Gateway.",
				Technical: "DNS enumeration of *.azurewebsites.net, *.azurefd.net; Application Gateway public IP reverse-looked up to reveal backend pool members.",
				Technique: "T1595.002",
				EnabledBy: "zt_net_014",
				Gain:      "Target URL and knowledge that no WAF policy protects the endpoint.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Probe the application for known vulnerabilities in the outdated runtime stack.",
				Technical: "Fingerprint the runtime version via response headers (X-Powered-By, Server); match against CVE databases for the specific .NET, Node, Python, or Java version deployed.",
				Technique: "T1190",
				EnabledBy: "zt_wl_017",
				Gain:      "Confirmed exploitable vulnerability in the runtime - e.g., deserialization RCE, path traversal, or SSRF.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Exploit the vulnerability to achieve remote code execution within the App Service sandbox.",
				Technical: "Payload delivered via HTTP request body; WAF would have blocked common patterns (union select, ../, java.lang.Runtime) but no WAF policy is attached to the Application Gateway.",
				Technique: "T1059.004",
				EnabledBy: "zt_net_014",
				Gain:      "Shell-level access inside the App Service container or Function App execution context.",
			},
			{
				Number:    4,
				Actor:     "Attacker inside App Service",
				Action:    "Harvest environment variables and query the managed identity endpoint for ARM and data-plane tokens.",
				Technical: "printenv reveals APPSETTING_* connection strings; curl $IDENTITY_ENDPOINT with $IDENTITY_HEADER yields bearer tokens for any resource the managed identity can access.",
				Technique: "T1552.005",
				EnabledBy: "zt_wl_017",
				Gain:      "Database connection strings, storage account keys, and a managed identity token for ARM.",
			},
			{
				Number:    5,
				Actor:     "Attacker with credentials",
				Action:    "Access backend SQL databases and storage accounts using harvested connection strings and tokens.",
				Technical: "sqlcmd with harvested SQL connection string; az storage blob download with managed identity token. Data exfiltrated over HTTPS egress.",
				Technique: "T1530",
				EnabledBy: "zt_wl_017",
				Gain:      "Full access to application data tier - customer PII, transaction records, secrets.",
			},
			{
				Number:    6,
				Actor:     "Attacker",
				Action:    "Maintain persistence undetected because no Application Insights telemetry captures anomalous request patterns or exception spikes.",
				Technical: "No Application Insights SDK or auto-instrumentation configured; request traces, dependency calls, and exception telemetry are never generated. SOC has zero application-layer visibility.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_019",
				Gain:      "Indefinite dwell time within the application tier with no application-level alerting.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Publicly-reachable App Service or Function App behind an Application Gateway with no WAF policy.",
			LateralMovement:    "App Service managed identity → backend SQL, Storage, Key Vault via harvested tokens and connection strings.",
			MaxPrivilege:       "Whatever role the App Service managed identity holds, plus direct database access via connection strings in environment variables.",
			DataAtRisk:         []string{"Application databases", "Storage account blobs", "Key Vault secrets referenced by app settings", "User session data"},
			ServicesAtRisk:     []string{"App Service", "Function Apps", "Application Gateway", "SQL Database", "Storage Accounts", "Key Vault"},
			EstimatedScopePerc: "Application tier + all backend data stores the app connects to",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "6.4.1 / 6.4.2", Impact: "Public-facing web applications are not protected by a WAF or equivalent; known vulnerabilities in runtime frameworks are not patched within required timeframes."},
			{Framework: "ISO 27001:2022", Control: "A.8.8 / A.8.9", Impact: "Technical vulnerability management and configuration management fail: outdated runtimes are deployed and no web application firewall compensates."},
			{Framework: "SOC 2", Control: "CC7.1 / CC8.1", Impact: "Detection mechanisms for malicious activity at the application layer are absent; change management does not ensure current runtime versions."},
		},
		MinimalFixSet: []string{"zt_net_014", "zt_wl_017"},
		PriorityFix: "Attach a WAF policy with OWASP 3.2 managed ruleset to the Application Gateway in Prevention mode immediately - this blocks the most common exploit payloads even before the runtime is patched. " +
			"Then upgrade all App Service and Function App runtime stacks to the latest supported versions.",
		BreakingNote: "WAF in Prevention mode may block legitimate requests that match OWASP rules (e.g., large file uploads, API payloads with SQL-like syntax). " +
			"Deploy in Detection mode first, review logs for false positives, then switch to Prevention.",
		MITRETechnique:    "T1190 / T1552.005",
		MITRETactic:       "Initial Access / Credential Access",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-033: PIM Abuse to Silent Privilege Escalation
// ---------------------------------------------------------------------------

func buildChain033(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_021", "zt_vis_017", "zt_id_019")
	triggers := collectFindingIDs(findings, "zt_id_021", "zt_vis_017", "zt_id_019")

	return &models.AttackChain{
		ID:                 "CHAIN-033",
		Title:              "PIM Abuse to Silent Privilege Escalation",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Privileged Identity Management is configured but critically weakened: eligible role assignments require no approval workflow, the Activity Log is not exported to a durable sink, " +
			"and access token lifetimes are set far beyond recommended thresholds. An attacker who compromises any PIM-eligible account can self-activate to Global Administrator or equivalent " +
			"without a second pair of eyes approving the request. The activation event is written to the Azure Activity Log, but since that log is not exported to Log Analytics or a SIEM, " +
			"no alert fires and the 90-day native retention silently expires the evidence. The long-lived token means the attacker holds the elevated privilege for hours - far longer than " +
			"the activation window - giving them time to establish persistence, exfiltrate data, and clean up before anyone notices.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker with compromised eligible account",
				Action:    "Enumerate PIM-eligible role assignments and identify high-privilege roles that require no approval.",
				Technical: "GET /beta/roleManagement/directory/roleEligibilityScheduleInstances; inspect each role's policy: approvalRequired=false, no approvers configured.",
				Technique: "T1087.004",
				EnabledBy: "zt_id_021",
				Gain:      "List of self-activatable privileged roles with no human gate.",
			},
			{
				Number:    2,
				Actor:     "Attacker",
				Action:    "Self-activate a Global Administrator or Privileged Role Administrator assignment through PIM.",
				Technical: "POST /beta/roleManagement/directory/roleAssignmentScheduleRequests with action=selfActivate, justification='Routine maintenance'; no approver is in the loop.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_021",
				Gain:      "Active Global Administrator role assignment for the configured activation duration.",
			},
			{
				Number:    3,
				Actor:     "Attacker with GA role",
				Action:    "Create a backdoor service principal with Owner role and a long-lived client secret for durable access.",
				Technical: "New-MgApplication + New-MgServicePrincipal + New-MgRoleAssignment; all audit events land in AuditLogs/ActivityLog.",
				Technique: "T1136.003",
				EnabledBy: "zt_vis_017",
				Gain:      "Persistent non-human identity that survives the PIM activation window.",
			},
			{
				Number:    4,
				Actor:     "Attacker",
				Action:    "Rely on the long-lived access token to continue operating after the PIM window would logically close.",
				Technical: "Token lifetime policy allows tokens valid for 4-8+ hours; even after PIM deactivation, cached tokens remain valid until expiry. ARM and Graph honor the token until exp claim.",
				Technique: "T1550.001",
				EnabledBy: "zt_id_019",
				Gain:      "Extended operational window well beyond the PIM activation period.",
			},
			{
				Number:    5,
				Actor:     "Attacker",
				Action:    "Exfiltrate sensitive data and erase traces, knowing the Activity Log is not forwarded.",
				Technical: "Activity Log events exist in the portal for 90 days but are not streamed to Log Analytics, Event Hub, or Storage. No SIEM correlation, no automated alert, no SOC ticket.",
				Technique: "T1070.009",
				EnabledBy: "zt_vis_017",
				Gain:      "Complete operational security - the activation, persistence, and exfiltration events age out of native retention with no one having seen them.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any account with PIM-eligible privileged role assignment.",
			LateralMovement:    "PIM self-activation → Global Administrator → service principal creation → any resource in the tenant.",
			MaxPrivilege:       "Global Administrator with no approval gate, extended by long-lived tokens.",
			DataAtRisk:         []string{"Entire Entra ID tenant", "All Azure subscriptions", "All Microsoft 365 data", "Key Vault secrets tenant-wide"},
			ServicesAtRisk:     []string{"Entra ID", "PIM", "All Azure subscriptions", "Microsoft 365", "Key Vault"},
			EstimatedScopePerc: "100% of the tenant",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "SOC 2", Control: "CC6.1 / CC6.3", Impact: "Privileged access requires no secondary authorization; separation of duties for critical role activation is absent."},
			{Framework: "NIST 800-53", Control: "AC-2(4) / AC-6(1) / AU-6", Impact: "Automated audit of account management actions fails; least privilege enforcement through PIM is undermined by missing approval gates."},
			{Framework: "ISO 27001:2022", Control: "A.5.15 / A.8.15", Impact: "Access control policy requires dual authorization for privilege escalation; logging and monitoring of privileged operations fail."},
		},
		MinimalFixSet: []string{"zt_id_021", "zt_vis_017"},
		PriorityFix: "Enable mandatory approval for all PIM-eligible roles at Global Administrator, Privileged Role Administrator, and User Access Administrator level. " +
			"Configure at least two approvers from a security team that is distinct from the eligible population. Export Activity Log to a Log Analytics workspace connected to Sentinel.",
		BreakingNote: "Requiring approval will slow down legitimate admin operations. Ensure the approval group has coverage across time zones and define an SLA for approval response. " +
			"Break-glass accounts must bypass PIM entirely and be monitored via a separate alert rule.",
		MITRETechnique:    "T1078.004 / T1550.001",
		MITRETactic:       "Privilege Escalation / Defense Evasion",
		KillChainPhase:    "Privilege Escalation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-034: Guest Account Lateral Movement
// ---------------------------------------------------------------------------

func buildChain034(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_016", "zt_id_017", "zt_id_013")
	triggers := collectFindingIDs(findings, "zt_id_016", "zt_id_017", "zt_id_013")

	return &models.AttackChain{
		ID:                 "CHAIN-034",
		Title:              "Guest Account Lateral Movement",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Guest user accounts in the tenant have permissions that exceed what B2B collaboration requires: they can read directory objects, enumerate group memberships, " +
			"and in some cases hold directory roles. Cross-tenant access settings use the default trust configuration, which honors MFA claims from the guest's home tenant - " +
			"meaning a guest who satisfies MFA in their own (potentially attacker-controlled) tenant is treated as MFA-compliant in yours. " +
			"No named locations are defined in Conditional Access, so there is no IP-based restriction on where guest sessions can originate. " +
			"An attacker who controls a guest account - or simply creates one from a throwaway tenant - authenticates from any IP, satisfies MFA in their own tenant, " +
			"and lands in your directory with read access to users, groups, applications, and any Azure RBAC roles the guest has been granted.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Accept a pending guest invitation or compromise an existing guest account via the guest's home tenant.",
				Technical: "Guest accounts are enumerated via Graph API or harvested from collaboration emails; the attacker controls the home tenant and can reset the guest's password there.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_017",
				Gain:      "Valid guest credential for the target tenant, with MFA satisfied in the attacker-controlled home tenant.",
			},
			{
				Number:    2,
				Actor:     "Attacker as guest",
				Action:    "Authenticate to the resource tenant from any IP address - no named location restriction blocks the session.",
				Technical: "Conditional Access evaluates the session: MFA claim is trusted from the home tenant via cross-tenant access defaults; no named location policy restricts guest sign-ins by IP.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_013",
				Gain:      "Authenticated guest session from an arbitrary location with full Conditional Access pass.",
			},
			{
				Number:    3,
				Actor:     "Attacker as guest",
				Action:    "Enumerate the directory: users, groups, applications, service principals, and role assignments.",
				Technical: "GET /v1.0/users, /v1.0/groups, /v1.0/applications - guest permissions are set to 'same as members' or the default which allows broad directory read.",
				Technique: "T1087.004",
				EnabledBy: "zt_id_016",
				Gain:      "Complete organizational chart, group membership graph, application inventory, and RBAC mapping.",
			},
			{
				Number:    4,
				Actor:     "Attacker as guest",
				Action:    "Leverage any Azure RBAC roles assigned to the guest account to access subscription resources.",
				Technical: "Guest holds Contributor or Reader on resource groups granted during collaboration; az resource list and az keyvault secret show succeed.",
				Technique: "T1580",
				EnabledBy: "zt_id_016",
				Gain:      "Access to Azure resources - potentially including Key Vaults, Storage Accounts, and databases - scoped to the guest's RBAC assignments.",
			},
			{
				Number:    5,
				Actor:     "Attacker as guest",
				Action:    "Use directory intelligence to craft targeted phishing or consent grant attacks against high-value internal users.",
				Technical: "Guest identifies Global Admins, their email addresses, group memberships, and recently registered applications; crafts spear-phish or illicit consent grant targeting those users.",
				Technique: "T1566.002",
				EnabledBy: "zt_id_016",
				Gain:      "Escalation path from guest-level access to compromised internal privileged account.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Guest account authenticated via attacker-controlled home tenant with MFA trust.",
			LateralMovement:    "Directory enumeration → targeted phishing of privileged users → RBAC-scoped resource access.",
			MaxPrivilege:       "Whatever RBAC roles and directory permissions the guest holds, plus intelligence for social engineering escalation.",
			DataAtRisk:         []string{"Directory metadata (users, groups, apps)", "Resources in guest RBAC scope", "Phishing targets for escalation"},
			ServicesAtRisk:     []string{"Entra ID", "Azure RBAC-scoped resources", "Key Vault", "Storage Accounts"},
			EstimatedScopePerc: "Directory-wide read + guest RBAC scope",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "ISO 27001:2022", Control: "A.5.19 / A.5.20", Impact: "Supplier and third-party access controls are not adequately restricted; guest accounts operate with excessive permissions."},
			{Framework: "NIST 800-53", Control: "AC-17 / AC-20", Impact: "Remote access and use of external information systems are not controlled; cross-tenant trust is implicitly granted."},
			{Framework: "SOC 2", Control: "CC6.1 / CC6.3", Impact: "Logical access controls for external entities do not enforce least privilege or geographic restrictions."},
		},
		MinimalFixSet: []string{"zt_id_016", "zt_id_013"},
		PriorityFix: "Restrict guest user permissions to 'most restrictive' in Entra ID external collaboration settings. Define named locations for corporate IP ranges and create a Conditional Access policy " +
			"that blocks guest sign-ins from outside those locations. Review and tighten cross-tenant access settings to not trust MFA from unmanaged tenants.",
		BreakingNote: "Restricting guest permissions may break B2B collaboration scenarios where guests legitimately need to enumerate groups or teams. " +
			"Audit existing guest workflows before tightening; use access packages in Entitlement Management to grant scoped access with expiry.",
		MITRETechnique:    "T1078.004 / T1087.004",
		MITRETactic:       "Initial Access / Discovery",
		KillChainPhase:    "Reconnaissance",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-035: Cognitive Services API Abuse to Data Exfil
// ---------------------------------------------------------------------------

func buildChain035(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_020", "zt_net_011", "zt_vis_011")
	triggers := collectFindingIDs(findings, "zt_data_020", "zt_net_011", "zt_vis_011")

	return &models.AttackChain{
		ID:                 "CHAIN-035",
		Title:              "Cognitive Services API Abuse to Data Exfil",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Azure Cognitive Services (including Azure OpenAI, Speech, Vision, and Language endpoints) are configured with public network access enabled and API keys that are not rotated or restricted. " +
			"No Azure Firewall or network virtual appliance inspects outbound traffic, and no centralized Log Analytics workspace aggregates diagnostic telemetry. " +
			"An attacker who obtains an API key - from a committed config file, a client-side application, or a compromised developer workstation - can call the Cognitive Services endpoints " +
			"from any IP worldwide. They abuse the AI/ML APIs to process, extract, and exfiltrate sensitive data: running OCR on confidential documents, using Language Understanding to extract " +
			"PII from text corpora, or using Azure OpenAI to summarize and exfiltrate proprietary content. No network control intercepts the traffic, and no logging captures the anomalous usage pattern.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Obtain a Cognitive Services API key from exposed source code, client-side JavaScript, or a compromised developer machine.",
				Technical: "GitHub dorking for 'cognitiveservices.azure.com' + key patterns; client-side SPAs that embed the key directly; environment variables on a compromised build agent.",
				Technique: "T1552.001",
				EnabledBy: "zt_data_020",
				Gain:      "Valid API key for one or more Cognitive Services endpoints.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Call the Cognitive Services REST API from an external network to validate the key and enumerate available models and deployments.",
				Technical: "GET https://{account}.cognitiveservices.azure.com/openai/deployments?api-version=2023-05-15 with Ocp-Apim-Subscription-Key header; public network access allows the call from any IP.",
				Technique: "T1526",
				EnabledBy: "zt_data_020",
				Gain:      "Confirmed working key and a list of deployed models, endpoints, and available capabilities.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Abuse the AI endpoints to process sensitive data: run OCR on uploaded documents, extract entities from text, or use chat completions to summarize proprietary content.",
				Technical: "POST /openai/deployments/{model}/chat/completions with attacker-supplied prompts referencing injected context; POST /vision/v3.2/ocr with uploaded images containing confidential documents.",
				Technique: "T1530",
				EnabledBy: "zt_net_011",
				Gain:      "AI-processed output containing extracted PII, summarized IP, or OCR text from confidential documents.",
			},
			{
				Number:    4,
				Actor:     "External attacker",
				Action:    "Exfiltrate processed data over HTTPS to attacker infrastructure, blending with normal API response traffic.",
				Technical: "All Cognitive Services responses return over HTTPS on port 443; no Azure Firewall or NVA inspects or restricts the traffic pattern. Exfil volume is masked by the API's own response payloads.",
				Technique: "T1041",
				EnabledBy: "zt_net_011",
				Gain:      "Extracted and structured sensitive data on attacker-controlled infrastructure.",
			},
			{
				Number:    5,
				Actor:     "External attacker",
				Action:    "Continue abuse undetected because no centralized logging captures Cognitive Services diagnostic events.",
				Technical: "Cognitive Services diagnostic settings are not configured to send to a Log Analytics workspace; no alert rule monitors abnormal request volumes, geographic anomalies, or unusual model usage patterns.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_011",
				Gain:      "Sustained API abuse with no detection or cost anomaly alert reaching the operations team.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Leaked Cognitive Services API key usable from any public IP.",
			LateralMovement:    "API key → Cognitive Services endpoints → AI-assisted data extraction and processing.",
			MaxPrivilege:       "Full data-plane access to all Cognitive Services resources sharing the compromised key.",
			DataAtRisk:         []string{"Documents processed by OCR/Vision", "Text processed by Language services", "Prompts and completions from OpenAI endpoints", "Training data and fine-tuned models"},
			ServicesAtRisk:     []string{"Azure Cognitive Services", "Azure OpenAI", "Computer Vision", "Language Understanding", "Speech Services"},
			EstimatedScopePerc: "All Cognitive Services resources accessible by the compromised key",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "GDPR", Control: "Article 32 / Article 35", Impact: "AI processing of personal data without network controls or monitoring fails the requirement for appropriate technical measures and data protection impact assessment."},
			{Framework: "ISO 27001:2022", Control: "A.8.11 / A.8.12", Impact: "Data masking and data leakage prevention are not applied to AI service endpoints processing sensitive content."},
			{Framework: "NIST 800-53", Control: "SC-7 / AU-12", Impact: "Boundary protection for AI service endpoints and audit generation for data-plane operations are absent."},
		},
		MinimalFixSet: []string{"zt_data_020", "zt_vis_011"},
		PriorityFix: "Disable public network access on all Cognitive Services accounts and configure private endpoints. Rotate all API keys immediately and migrate to Managed Identity authentication where possible. " +
			"Enable diagnostic settings to send Cognitive Services logs to a centralized Log Analytics workspace.",
		BreakingNote: "Disabling public access will break any client application that calls the Cognitive Services endpoint from outside the VNet. " +
			"Ensure private DNS zones are configured and client applications route through the private endpoint or a VPN/ExpressRoute before applying.",
		MITRETechnique:    "T1552.001 / T1530",
		MITRETactic:       "Credential Access / Collection",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-036: Service Bus Message Interception
// ---------------------------------------------------------------------------

func buildChain036(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_019", "zt_data_018", "zt_vis_016")
	triggers := collectFindingIDs(findings, "zt_data_019", "zt_data_018", "zt_vis_016")

	return &models.AttackChain{
		ID:                 "CHAIN-036",
		Title:              "Service Bus Message Interception",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Azure Service Bus namespaces are accessible over public endpoints, Event Hub does not enforce customer-managed key encryption for data at rest, " +
			"and storage diagnostic logging is disabled. An attacker who obtains a Service Bus connection string - from a leaked configuration, a compromised application, " +
			"or an overly-broad SAS policy - can connect from any IP to receive, peek, or dead-letter messages in queues and topic subscriptions. " +
			"Messages flowing through the Event Hub that feeds downstream analytics are encrypted only with Microsoft-managed keys, giving the attacker confidence that " +
			"a compromised storage account or export path yields readable data. With storage diagnostic logging off, the operations team has no audit trail of who accessed what, " +
			"when, or how many messages were intercepted.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Harvest a Service Bus connection string or SAS token from a compromised application, repository, or configuration store.",
				Technical: "Connection strings containing Endpoint=sb://{namespace}.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=... found in app settings, committed code, or environment variables.",
				Technique: "T1552.001",
				EnabledBy: "zt_data_019",
				Gain:      "Valid Service Bus credential with Send/Listen/Manage rights on the namespace.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Connect to the public Service Bus endpoint and enumerate queues, topics, and subscriptions.",
				Technical: "ServiceBusAdministrationClient.getQueues() / getTopics() over the public endpoint; no IP firewall rule restricts the source. RootManageSharedAccessKey has Manage rights on the entire namespace.",
				Technique: "T1526",
				EnabledBy: "zt_data_019",
				Gain:      "Full inventory of messaging entities and their message counts.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Receive or peek messages from production queues, intercepting business-critical payloads.",
				Technical: "ServiceBusReceiverClient.receiveMessages() in PeekLock or ReceiveAndDelete mode; messages contain order data, PII, authentication tokens, or inter-service commands.",
				Technique: "T1557",
				EnabledBy: "zt_data_019",
				Gain:      "Real-time interception of application message traffic including sensitive business data.",
			},
			{
				Number:    4,
				Actor:     "External attacker",
				Action:    "Access Event Hub capture blobs in the linked storage account, reading historical message archives.",
				Technical: "Event Hub capture writes Avro files to a storage container; without CMK, the attacker who gains storage access reads plaintext payloads. Microsoft-managed keys provide no customer-controlled revocation.",
				Technique: "T1530",
				EnabledBy: "zt_data_018",
				Gain:      "Historical message archive spanning days or weeks of business transactions.",
			},
			{
				Number:    5,
				Actor:     "External attacker",
				Action:    "Operate without detection because storage diagnostic logging is disabled on the capture storage account.",
				Technical: "StorageRead, StorageWrite, and StorageDelete diagnostic categories are not enabled; no log entry records the attacker's blob downloads from the capture container.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_016",
				Gain:      "Complete absence of forensic evidence for the message interception and data exfiltration.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Leaked Service Bus connection string usable from any public IP.",
			LateralMovement:    "Service Bus namespace → Event Hub capture → linked Storage Account.",
			MaxPrivilege:       "Full data-plane access to all queues, topics, subscriptions, and captured message archives in the namespace.",
			DataAtRisk:         []string{"Real-time message payloads", "Historical Event Hub capture archives", "Business transaction data", "Inter-service authentication tokens", "Customer PII in message bodies"},
			ServicesAtRisk:     []string{"Azure Service Bus", "Azure Event Hub", "Azure Storage (capture)", "Downstream consumers"},
			EstimatedScopePerc: "All messaging entities in the namespace + capture storage",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "3.5 / 4.1", Impact: "Cardholder data in transit through messaging systems is not protected by customer-controlled encryption; access to message stores is not restricted by network controls."},
			{Framework: "GDPR", Control: "Article 32", Impact: "Personal data flowing through messaging infrastructure lacks appropriate access controls and encryption measures under customer control."},
			{Framework: "SOC 2", Control: "CC6.1 / CC6.7", Impact: "Logical access to messaging infrastructure is not restricted to authorized endpoints; data transmission controls are insufficient."},
		},
		MinimalFixSet: []string{"zt_data_019", "zt_vis_016"},
		PriorityFix: "Enable the Service Bus namespace IP firewall to restrict access to known VNets and IPs. Rotate all SAS keys and migrate to Managed Identity authentication. " +
			"Enable storage diagnostic logging on all storage accounts used for Event Hub capture.",
		BreakingNote: "Enabling the IP firewall will block any application connecting from outside the allowed IP ranges, including developer workstations, CI/CD agents, and multi-region deployments. " +
			"Inventory all legitimate callers before applying the restriction.",
		MITRETechnique:    "T1557 / T1530",
		MITRETactic:       "Collection / Credential Access",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-037: VPN Downgrade to Network Intrusion
// ---------------------------------------------------------------------------

func buildChain037(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_015", "zt_net_016", "zt_net_020")
	triggers := collectFindingIDs(findings, "zt_net_015", "zt_net_016", "zt_net_020")

	return &models.AttackChain{
		ID:                 "CHAIN-037",
		Title:              "VPN Downgrade to Network Intrusion",
		Severity:           "MEDIUM",
		Likelihood:         "Low",
		EnvironmentSummary: envSummary(resources),
		Narrative: "The Azure VPN Gateway is configured to accept IKEv1 connections instead of enforcing IKEv2, Network Watcher is not provisioned in all regions where resources are deployed, " +
			"and VNet peering relationships allow forwarded traffic. IKEv1 has known cryptographic weaknesses - it supports aggressive mode which exposes the pre-shared key hash, " +
			"and its Phase 1 negotiation is vulnerable to offline brute-force attacks. An attacker on the network path (ISP-level or co-located facility) captures the IKEv1 aggressive-mode exchange, " +
			"brute-forces the PSK offline, and establishes a rogue VPN tunnel into the Azure VNet. Once inside, the permissive peering configuration that allows forwarded traffic lets the attacker " +
			"pivot from the landing VNet to every peered VNet. Network Watcher is missing in the regions involved, so no NSG flow logs, packet captures, or connection monitors detect the intrusion.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Network-positioned attacker",
				Action:    "Capture the IKEv1 aggressive-mode exchange between the on-premises gateway and the Azure VPN Gateway.",
				Technical: "IKEv1 aggressive mode transmits the identity and hash in the clear in the first message; tcpdump on the ISP path or a compromised on-prem device captures the exchange.",
				Technique: "T1040",
				EnabledBy: "zt_net_015",
				Gain:      "Captured IKEv1 Phase 1 hash containing the pre-shared key material.",
			},
			{
				Number:    2,
				Actor:     "Attacker",
				Action:    "Brute-force the pre-shared key offline using the captured hash.",
				Technical: "ike-scan + psk-crack or hashcat mode 5300 against the captured aggressive-mode hash; weak or short PSKs fall within hours.",
				Technique: "T1110.002",
				EnabledBy: "zt_net_015",
				Gain:      "The plaintext pre-shared key for the VPN tunnel.",
			},
			{
				Number:    3,
				Actor:     "Attacker with PSK",
				Action:    "Establish a rogue IKEv1 tunnel to the Azure VPN Gateway, impersonating the legitimate on-premises peer.",
				Technical: "Configure strongSwan or libreswan with the recovered PSK and the Azure VPN Gateway's public IP; the gateway accepts the connection because IKEv1 is enabled and the PSK matches.",
				Technique: "T1133",
				EnabledBy: "zt_net_015",
				Gain:      "Network-level access to the Azure VNet address space via the VPN tunnel.",
			},
			{
				Number:    4,
				Actor:     "Attacker inside VNet",
				Action:    "Pivot through VNet peerings that allow forwarded traffic to reach workloads in other VNets.",
				Technical: "VNet peering with allowForwardedTraffic=true and allowGatewayTransit=true; traffic from the VPN tunnel is forwarded into peered VNets without additional authentication.",
				Technique: "T1021",
				EnabledBy: "zt_net_020",
				Gain:      "Access to every VNet in the peering mesh - database subnets, application tiers, management networks.",
			},
			{
				Number:    5,
				Actor:     "Attacker",
				Action:    "Operate undetected because Network Watcher is not deployed in the affected regions.",
				Technical: "No NSG flow logs capture the anomalous traffic; no packet capture capability exists for incident response; Connection Monitor does not flag the new tunnel establishment.",
				Technique: "T1562.008",
				EnabledBy: "zt_net_016",
				Gain:      "No network-layer detection or forensic capability in the compromised regions.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Rogue VPN tunnel established via brute-forced IKEv1 pre-shared key.",
			LateralMovement:    "VPN landing VNet → all peered VNets via forwarded traffic allowance.",
			MaxPrivilege:       "Network-level access to every subnet in the peering topology.",
			DataAtRisk:         []string{"All network-accessible services in peered VNets", "Database instances on private subnets", "Internal APIs and management interfaces"},
			ServicesAtRisk:     []string{"VPN Gateway", "All VNet-peered workloads", "SQL on private endpoints", "Internal load balancers"},
			EstimatedScopePerc: "All VNets in the peering mesh",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "2.2.7 / 4.2.1", Impact: "Strong cryptography is not enforced for VPN tunnels protecting cardholder data; IKEv1 does not meet current cryptographic standards."},
			{Framework: "NIST 800-53", Control: "SC-8 / SC-13", Impact: "Transmission confidentiality and cryptographic protection use deprecated protocols that do not meet FIPS 140-2 requirements."},
			{Framework: "ISO 27001:2022", Control: "A.8.20 / A.8.21", Impact: "Network security controls and security of network services fail when VPN tunnels accept deprecated protocol versions."},
		},
		MinimalFixSet: []string{"zt_net_015", "zt_net_016"},
		PriorityFix: "Reconfigure the VPN Gateway to enforce IKEv2 only and use certificate-based authentication instead of pre-shared keys. " +
			"Deploy Network Watcher in every region with active resources and enable NSG flow logs on all network security groups.",
		BreakingNote: "Enforcing IKEv2 will disconnect any site-to-site or point-to-site client that only supports IKEv1. " +
			"Coordinate with on-premises network teams to verify IKEv2 compatibility before making the change. Legacy VPN concentrators may need firmware upgrades.",
		MITRETechnique:    "T1133 / T1040",
		MITRETactic:       "Initial Access / Lateral Movement",
		KillChainPhase:    "Delivery",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-038: Front Door Exploit Chain
// ---------------------------------------------------------------------------

func buildChain038(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_017", "zt_net_013", "zt_wl_019")
	triggers := collectFindingIDs(findings, "zt_net_017", "zt_net_013", "zt_wl_019")

	return &models.AttackChain{
		ID:                 "CHAIN-038",
		Title:              "Front Door Exploit Chain",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Azure Front Door is deployed as the internet-facing edge but has no WAF policy attached, the subscription lacks Azure DDoS Protection Standard, " +
			"and backend App Services do not require client certificates for mutual TLS. This triple gap creates a devastating attack surface: " +
			"the attacker launches L7 application-layer attacks through Front Door unfiltered - SQL injection, XSS, bot scraping, credential stuffing - because no WAF rule inspects the payload. " +
			"Simultaneously or as a diversion, they launch a volumetric DDoS attack that the Basic tier cannot mitigate, saturating the backend and masking the application-layer exploit. " +
			"The backend App Service accepts any connection forwarded by Front Door without verifying a client certificate, so an attacker who discovers the backend FQDN directly " +
			"(*.azurewebsites.net) can bypass Front Door entirely and hit the origin with no protection layer whatsoever.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Enumerate the Front Door endpoint and identify that no WAF policy is attached.",
				Technical: "DNS lookup of *.azurefd.net; HTTP response headers reveal Front Door without X-Azure-FDID WAF markers; no 403 responses on common attack patterns confirm WAF absence.",
				Technique: "T1595.002",
				EnabledBy: "zt_net_017",
				Gain:      "Confirmed unprotected Front Door endpoint accepting arbitrary HTTP payloads.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Launch a volumetric DDoS attack against the Front Door and backend IPs to degrade availability and distract the operations team.",
				Technical: "UDP/TCP flood targeting the Front Door anycast IPs; DDoS Protection Basic provides only limited mitigation at volumes above ~300 Mbps, with no custom policies or alerting.",
				Technique: "T1498.001",
				EnabledBy: "zt_net_013",
				Gain:      "Backend degradation, ops team focused on availability, reduced capacity for security investigation.",
			},
			{
				Number:    3,
				Actor:     "External attacker",
				Action:    "Simultaneously deliver L7 application-layer attacks through Front Door targeting the unprotected backend.",
				Technical: "SQL injection, SSRF, command injection payloads in HTTP requests; no WAF managed ruleset to detect or block OWASP Top 10 attack patterns.",
				Technique: "T1190",
				EnabledBy: "zt_net_017",
				Gain:      "Application-layer compromise of the backend service - code execution, data access, or authentication bypass.",
			},
			{
				Number:    4,
				Actor:     "External attacker",
				Action:    "Discover the backend App Service FQDN and connect directly, bypassing Front Door entirely.",
				Technical: "DNS brute-force of *.azurewebsites.net; certificate transparency logs reveal the backend hostname. Direct connection succeeds because App Service does not require client certificates.",
				Technique: "T1190",
				EnabledBy: "zt_wl_019",
				Gain:      "Direct origin access with no CDN caching, no rate limiting, no WAF - even if a WAF is later added to Front Door.",
			},
			{
				Number:    5,
				Actor:     "Attacker with backend access",
				Action:    "Exfiltrate data from the compromised backend while the DDoS attack continues to distract defenders.",
				Technical: "Data extracted via HTTPS to attacker-controlled endpoints; operations team is triaging the availability incident and not monitoring data-plane exfiltration.",
				Technique: "T1041",
				EnabledBy: "zt_net_013",
				Gain:      "Customer data, application secrets, and database contents exfiltrated under the cover of a DDoS smokescreen.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Unfiltered Front Door endpoint or direct backend App Service access.",
			LateralMovement:    "Front Door → backend App Service → managed identity → connected data stores.",
			MaxPrivilege:       "Application-level access to backend services plus whatever the App Service managed identity holds.",
			DataAtRisk:         []string{"All data served by the backend application", "Connected database contents", "Application secrets and connection strings", "User session tokens"},
			ServicesAtRisk:     []string{"Azure Front Door", "App Service", "Connected SQL/Cosmos databases", "Storage accounts", "Key Vault"},
			EstimatedScopePerc: "All backend services behind the Front Door profile",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "6.4.1 / 6.4.2", Impact: "Web application firewall is not deployed on the internet-facing edge; public-facing applications are not protected against known attack vectors."},
			{Framework: "ISO 27001:2022", Control: "A.8.20 / A.8.26", Impact: "Network security and application security controls at the edge fail to filter malicious traffic or enforce mutual authentication."},
			{Framework: "SOC 2", Control: "CC6.6 / A1.2", Impact: "System boundaries lack controls to prevent unauthorized access; availability commitments are at risk without DDoS mitigation."},
		},
		MinimalFixSet: []string{"zt_net_017", "zt_wl_019"},
		PriorityFix: "Attach a WAF policy with OWASP 3.2 managed ruleset and bot protection to the Front Door profile in Prevention mode. " +
			"Configure the backend App Service to require client certificates and validate the Front Door certificate thumbprint, blocking direct origin access.",
		BreakingNote: "Requiring client certificates on the App Service will break any direct access to the backend FQDN, including health probes from services other than Front Door. " +
			"Ensure all traffic routes through Front Door and update any non-Front-Door health checks before enabling mutual TLS.",
		MITRETechnique:    "T1190 / T1498.001",
		MITRETactic:       "Initial Access / Impact",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-039: AKS Secrets Exposure to Data Breach
// ---------------------------------------------------------------------------

func buildChain039(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_022", "zt_wl_014", "zt_data_014")
	triggers := collectFindingIDs(findings, "zt_wl_022", "zt_wl_014", "zt_data_014")

	return &models.AttackChain{
		ID:                 "CHAIN-039",
		Title:              "AKS Secrets Exposure to Data Breach",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "AKS clusters are not using the Azure Key Vault CSI driver, meaning application secrets - database passwords, API keys, connection strings - are stored as Kubernetes Secrets " +
			"(base64-encoded, not encrypted at the application layer) or injected directly as environment variables in pod specs. No Kubernetes network policy restricts pod-to-pod traffic, " +
			"and the Key Vault that would be the correct secrets store has purge protection disabled. An attacker who gains access to any pod in the cluster - via an application vulnerability, " +
			"a compromised container image, or kubectl exec through a stolen kubeconfig - can read every secret in the namespace from environment variables or the Kubernetes API. " +
			"Those secrets unlock the Key Vault, where the attacker can read all remaining secrets and, critically, permanently delete (purge) them to destroy evidence or cause maximum damage.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker with pod access",
				Action:    "Read secrets from environment variables and Kubernetes Secret objects in the pod's namespace.",
				Technical: "printenv reveals DATABASE_PASSWORD, API_KEY, CONN_STRING injected via env: valueFrom: secretKeyRef; kubectl get secrets -o yaml returns base64-encoded values trivially decoded.",
				Technique: "T1552.007",
				EnabledBy: "zt_wl_022",
				Gain:      "Plaintext application secrets including database credentials, API keys, and Key Vault access credentials.",
			},
			{
				Number:    2,
				Actor:     "Attacker inside cluster",
				Action:    "Move laterally to other pods and namespaces due to absent network policies.",
				Technical: "No NetworkPolicy objects defined; all pods can communicate with all other pods on any port. Attacker scans the cluster CIDR (10.244.0.0/16) for services and databases.",
				Technique: "T1046",
				EnabledBy: "zt_wl_014",
				Gain:      "Access to every service in the cluster - databases, caches, internal APIs - from any compromised pod.",
			},
			{
				Number:    3,
				Actor:     "Attacker with harvested credentials",
				Action:    "Authenticate to Azure Key Vault using the service principal credentials or managed identity token found in environment variables.",
				Technical: "az keyvault secret list --vault-name {name} using AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID harvested from pod env vars; or use the pod's workload identity token.",
				Technique: "T1555.006",
				EnabledBy: "zt_wl_022",
				Gain:      "Read access to all secrets in the Key Vault - TLS certificates, encryption keys, additional service credentials.",
			},
			{
				Number:    4,
				Actor:     "Attacker with Key Vault access",
				Action:    "Exfiltrate all Key Vault secrets and then purge the vault to destroy evidence and maximize impact.",
				Technical: "az keyvault secret download for each secret; then az keyvault delete followed by az keyvault purge. Purge protection is disabled, so the soft-deleted vault is permanently destroyed.",
				Technique: "T1485",
				EnabledBy: "zt_data_014",
				Gain:      "All secrets exfiltrated to attacker infrastructure; Key Vault and all its contents permanently destroyed with no recovery possible.",
			},
			{
				Number:    5,
				Actor:     "Attacker",
				Action:    "Use exfiltrated database credentials and API keys to access production data stores directly from outside the cluster.",
				Technical: "SQL connection strings, Cosmos DB keys, and Storage account keys from the vault used to connect to data stores over their public or private endpoints.",
				Technique: "T1530",
				EnabledBy: "zt_wl_022",
				Gain:      "Full production data breach - customer records, financial data, PII - with the Key Vault destroyed to hamper incident response.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any pod in the AKS cluster via application vulnerability, supply chain, or stolen kubeconfig.",
			LateralMovement:    "Pod → all namespaces (no network policy) → Key Vault → external data stores.",
			MaxPrivilege:       "Key Vault data-plane access with purge capability plus direct database access via harvested credentials.",
			DataAtRisk:         []string{"All Kubernetes Secrets in the cluster", "All Key Vault secrets", "Production databases", "Storage account contents", "TLS private keys"},
			ServicesAtRisk:     []string{"AKS", "Key Vault", "SQL Database", "Cosmos DB", "Storage Accounts", "Any service whose credentials were in the vault"},
			EstimatedScopePerc: "Cluster + all backend data stores referenced by application secrets",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "3.5 / 8.3.2", Impact: "Cryptographic keys and authentication credentials are stored in plaintext environment variables; key management lifecycle controls are absent when Key Vault can be purged."},
			{Framework: "ISO 27001:2022", Control: "A.8.24 / A.8.10", Impact: "Cryptography and information deletion controls fail: secrets are not encrypted at the application layer and the key store can be irreversibly destroyed."},
			{Framework: "NIST 800-53", Control: "SC-12 / SC-28", Impact: "Cryptographic key establishment and protection of information at rest fail when secrets are stored as base64 Kubernetes objects."},
		},
		MinimalFixSet: []string{"zt_wl_022", "zt_data_014"},
		PriorityFix: "Deploy the Azure Key Vault CSI driver on all AKS clusters and migrate all secrets from Kubernetes Secrets and environment variables to Key Vault-backed SecretProviderClass resources. " +
			"Enable purge protection on all Key Vaults immediately - this is a one-way setting that permanently prevents vault destruction.",
		BreakingNote: "Migrating to the CSI driver requires changes to every pod spec that references secrets via env vars or volume mounts. " +
			"Roll out namespace-by-namespace with canary deployments. Enabling purge protection is irreversible and extends soft-delete retention; ensure retention period aligns with compliance requirements.",
		MITRETechnique:    "T1552.007 / T1485",
		MITRETactic:       "Credential Access / Impact",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-040: Identity Protection Gap to Account Takeover
// ---------------------------------------------------------------------------

func buildChain040(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_018", "zt_id_022", "zt_id_015")
	triggers := collectFindingIDs(findings, "zt_id_018", "zt_id_022", "zt_id_015")

	return &models.AttackChain{
		ID:                 "CHAIN-040",
		Title:              "Identity Protection Gap to Account Takeover",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Entra ID Identity Protection is effectively disabled: no sign-in risk policy detects anomalous authentication patterns (impossible travel, password spray indicators, " +
			"anonymous IP usage), and no user risk policy flags accounts whose credentials have appeared in dark web breaches. Self-Service Password Reset is configured with weak " +
			"authentication methods - a single SMS or security question - rather than requiring strong factors. This creates a complete identity protection vacuum. " +
			"An attacker password-sprays the tenant, compromises an account, and Entra never raises a sign-in risk event because the policy is not enabled. " +
			"The compromised account is never flagged as 'at risk' because no user risk policy processes the signals. The attacker then uses SSPR with a weak method " +
			"to reset the password, locking out the legitimate user and establishing full control of the account. From there, the attacker resets other accounts using " +
			"the same SSPR weakness, creating a cascading compromise that Identity Protection would have stopped at step one.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Execute a low-and-slow password spray against the tenant's authentication endpoints.",
				Technical: "Spray one common password against thousands of accounts per hour via https://login.microsoftonline.com/common/oauth2/token; stay below smart lockout thresholds.",
				Technique: "T1110.003",
				EnabledBy: "zt_id_018",
				Gain:      "One or more valid username/password pairs. Sign-in risk policy would have flagged the spray pattern - but it is not enabled.",
			},
			{
				Number:    2,
				Actor:     "Attacker with valid credentials",
				Action:    "Authenticate as the compromised user; Entra ID does not challenge or block the anomalous sign-in.",
				Technical: "Sign-in from an anonymous VPN IP with impossible travel from the user's last known location; Identity Protection generates the risk signal internally but no policy acts on it.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_018",
				Gain:      "Full session access as the compromised user with no risk-based Conditional Access challenge.",
			},
			{
				Number:    3,
				Actor:     "Attacker",
				Action:    "Initiate Self-Service Password Reset using a weak method to change the password and lock out the legitimate user.",
				Technical: "SSPR flow at https://passwordreset.microsoftonline.com/ accepts a single SMS verification or security question; attacker has harvested the phone number via social engineering or SIM swap.",
				Technique: "T1098.005",
				EnabledBy: "zt_id_015",
				Gain:      "Full account takeover: password changed, legitimate user locked out, attacker is now the sole credential holder.",
			},
			{
				Number:    4,
				Actor:     "Attacker with account control",
				Action:    "Register new MFA methods and disable the old ones to cement persistence.",
				Technical: "Navigate to https://mysignins.microsoft.com/security-info; register attacker-controlled authenticator app; remove victim's phone number. No user risk policy flags this as suspicious.",
				Technique: "T1556.006",
				EnabledBy: "zt_id_022",
				Gain:      "Durable MFA persistence - even if the password is reset by IT, the attacker's MFA method remains registered.",
			},
			{
				Number:    5,
				Actor:     "Attacker",
				Action:    "Use the compromised account's access to target additional high-value accounts via the same SSPR weakness.",
				Technical: "If the compromised account has Helpdesk or User Administrator role, directly reset passwords for other users. Otherwise, use directory enumeration to identify targets and repeat the SSPR attack.",
				Technique: "T1136.003",
				EnabledBy: "zt_id_015",
				Gain:      "Cascading account compromise across the tenant, potentially reaching Global Administrator accounts.",
			},
			{
				Number:    6,
				Actor:     "Attacker with multiple accounts",
				Action:    "Exfiltrate data, establish persistence, and prepare for destructive action across the compromised accounts.",
				Technical: "Access SharePoint, Exchange, Teams data across all compromised identities; create backdoor app registrations; grant consent to malicious applications.",
				Technique: "T1530",
				EnabledBy: "zt_id_022",
				Gain:      "Broad tenant compromise with persistent access across multiple identities and no Identity Protection remediation trigger.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Password spray against tenant authentication endpoints, undetected by absent sign-in risk policy.",
			LateralMovement:    "Compromised account → SSPR takeover of additional accounts → cascading identity compromise.",
			MaxPrivilege:       "Whatever roles the compromised accounts hold, potentially escalating to Global Administrator via cascading SSPR attacks.",
			DataAtRisk:         []string{"All data accessible to compromised identities", "Exchange mailboxes", "SharePoint/OneDrive files", "Teams messages", "Azure resource data"},
			ServicesAtRisk:     []string{"Entra ID", "Exchange Online", "SharePoint Online", "OneDrive", "Microsoft Teams", "Azure subscriptions"},
			EstimatedScopePerc: "Potentially 100% of the tenant if cascading compromise reaches Global Administrator",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "IA-5(1) / SI-4", Impact: "Authenticator management does not detect compromised credentials; information system monitoring for identity-based attacks is absent."},
			{Framework: "PCI DSS 4.0", Control: "8.3 / 8.6", Impact: "Strong authentication requirements are undermined by weak SSPR methods; compromised credential detection is not implemented."},
			{Framework: "SOC 2", Control: "CC6.1 / CC6.8", Impact: "Logical access controls fail to detect and respond to compromised credentials; preventive and detective controls for identity threats are absent."},
		},
		MinimalFixSet: []string{"zt_id_018", "zt_id_015"},
		PriorityFix: "Enable the sign-in risk policy at minimum 'Medium and above' risk requiring MFA, and the user risk policy at 'High' risk requiring password change. " +
			"Reconfigure SSPR to require two strong methods (authenticator app + phone) and disable security questions as an SSPR method entirely.",
		BreakingNote: "Enabling risk policies may trigger MFA challenges or forced password resets for users whose sessions are already flagged as risky by Identity Protection's backlog. " +
			"Communicate to the helpdesk before enabling and prepare for a spike in support tickets in the first 48 hours. " +
			"Changing SSPR methods will require users to re-register; use the combined registration experience and set a registration deadline.",
		MITRETechnique:    "T1110.003 / T1098.005",
		MITRETactic:       "Credential Access / Persistence",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-041: Complete Visibility Blind Spot
// ---------------------------------------------------------------------------

func buildChain041(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_vis_011", "zt_vis_017", "zt_vis_018")
	triggers := collectFindingIDs(findings, "zt_vis_011", "zt_vis_017", "zt_vis_018")

	return &models.AttackChain{
		ID:                 "CHAIN-041",
		Title:              "Complete Visibility Blind Spot",
		Severity:           "HIGH",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "The environment has achieved total visibility blindness. No Log Analytics workspace exists to aggregate telemetry, the Azure Activity Log is not exported to any durable sink, " +
			"and no Action Groups are configured to route alerts to human responders. Every other security control in the environment is operating in the dark: " +
			"Defender for Cloud may generate recommendations, NSGs may log flows, Identity Protection may detect risks - but none of that matters because no one is watching, " +
			"no telemetry is retained beyond default periods, and no alert ever reaches a phone, inbox, or Slack channel. This is not a single missing log source; " +
			"it is a systemic architectural failure that renders the entire security posture decorative. Any attacker who gains any foothold operates with effectively " +
			"infinite dwell time because the feedback loop from detection to response does not exist.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Any attacker with any initial access vector",
				Action:    "Confirm that no centralized logging infrastructure exists by observing the absence of monitoring responses to deliberately noisy actions.",
				Technical: "Create a test resource group, modify an NSG rule, trigger a sign-in from an anomalous location - wait for any response. None comes because no Log Analytics workspace ingests the events.",
				Technique: "T1497.001",
				EnabledBy: "zt_vis_011",
				Gain:      "Certainty that actions are not being monitored or correlated.",
			},
			{
				Number:    2,
				Actor:     "Attacker",
				Action:    "Perform privilege escalation and persistence actions that emit Activity Log events, knowing those events are not exported.",
				Technical: "Role assignments, policy exemptions, resource locks removed, diagnostic settings deleted - all generate Activity Log entries that exist only in the portal for 90 days with no export.",
				Technique: "T1098",
				EnabledBy: "zt_vis_017",
				Gain:      "Privilege escalation with a 90-day evidence expiry timer that is ticking in the attacker's favor.",
			},
			{
				Number:    3,
				Actor:     "Attacker",
				Action:    "Establish multiple persistence mechanisms knowing that even if a control detects one, no alert will reach a human.",
				Technical: "Backdoor service principal, modified Conditional Access policy, new PIM eligible assignment, webhook on a Logic App - each would generate an alert in a configured environment, but no Action Group exists.",
				Technique: "T1136.003",
				EnabledBy: "zt_vis_018",
				Gain:      "Redundant persistence across identity, workload, and automation layers.",
			},
			{
				Number:    4,
				Actor:     "Attacker",
				Action:    "Exfiltrate data at leisure over days or weeks, adjusting pace based on the complete absence of defensive response.",
				Technical: "Staged exfiltration via Storage Account copy, Logic App export, or Graph API bulk download - no anomaly detection, no bandwidth alert, no SOC analyst review.",
				Technique: "T1567.002",
				EnabledBy: "zt_vis_011",
				Gain:      "Complete data exfiltration with zero detection pressure.",
			},
			{
				Number:    5,
				Actor:     "Attacker",
				Action:    "Optionally execute destructive actions knowing that incident response cannot begin until a user manually notices something is wrong.",
				Technical: "Resource deletion, encryption with attacker-controlled keys, DNS hijacking - the mean time to detect is measured in days or weeks because the only detection mechanism is a human noticing a broken application.",
				Technique: "T1485",
				EnabledBy: "zt_vis_018",
				Gain:      "Maximum impact with maximum dwell time; incident response starts from zero context because no historical telemetry exists.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any initial access vector - this chain amplifies every other attack by removing detection.",
			LateralMovement:    "Unrestricted - no visibility means no detection at any stage of lateral movement.",
			MaxPrivilege:       "Whatever the attacker accumulates over an unlimited dwell time.",
			DataAtRisk:         []string{"All data in the environment", "Historical forensic data is unrecoverable", "Incident response starts from zero"},
			ServicesAtRisk:     []string{"All Azure services", "All Entra ID objects", "All Microsoft 365 workloads"},
			EstimatedScopePerc: "100% - visibility failure is environment-wide",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "SOC 2", Control: "CC7.1 / CC7.2 / CC7.3", Impact: "The entire monitoring, detection, and response lifecycle is absent: events are not detected, incidents are not evaluated, and responses are not executed."},
			{Framework: "PCI DSS 4.0", Control: "10.1 / 10.2 / 10.7", Impact: "Audit log mechanisms are not active, audit trail capture is not implemented, and prompt detection of security system failures is impossible."},
			{Framework: "NIST 800-53", Control: "AU-2 / AU-6 / IR-4 / SI-4", Impact: "Auditable events are not defined, audit review and analysis are absent, incident handling cannot trigger, and information system monitoring does not exist."},
			{Framework: "ISO 27001:2022", Control: "A.8.15 / A.8.16", Impact: "Logging and monitoring of activities and anomaly detection are completely absent across the environment."},
		},
		MinimalFixSet: []string{"zt_vis_011", "zt_vis_018"},
		PriorityFix: "Deploy a Log Analytics workspace and configure Activity Log export to it as diagnostic setting at the subscription level. " +
			"Create Action Groups with email, SMS, and webhook targets for the security operations team. " +
			"Then enable Defender for Cloud alert forwarding and create baseline alert rules for critical operations (role assignments, policy changes, resource deletions).",
		BreakingNote: "Log Analytics ingestion costs scale with data volume. Start with Activity Logs and Entra ID sign-in/audit logs to establish baseline visibility, " +
			"then expand to resource-level diagnostics. Budget for a commitment tier based on projected ingestion. " +
			"Action Groups will generate alert noise initially - tune alert rules iteratively to reduce false positives without creating alert fatigue.",
		MITRETechnique:    "T1562.008 / T1098",
		MITRETactic:       "Defense Evasion / Persistence",
		KillChainPhase:    "Persistence",
		AffectedResources: resources,
	}
}
// ---------------------------------------------------------------------------
// CHAIN-042: VM Disk Theft to Offline Data Exfil
// ---------------------------------------------------------------------------

func buildChain042(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_020", "zt_data_017", "zt_vis_012")
	triggers := collectFindingIDs(findings, "zt_wl_020", "zt_data_017", "zt_vis_012")

	return &models.AttackChain{
		ID:                 "CHAIN-042",
		Title:              "VM disk theft to offline data exfiltration",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "A virtual machine's OS and data disks are not encrypted with Azure Disk Encryption or EncryptionAtHost, meaning the underlying VHD blobs " +
			"store data in the clear at the platform layer. An attacker who gains even Reader + Disk Snapshot Contributor rights " +
			"(commonly available to developer-role identities) can snapshot the disk, share the snapshot to an external subscription, " +
			"and mount it offline to read every file on the volume - database files, credential caches, application secrets, memory dumps. " +
			"Because Azure Backup is not configured for these VMs, the organisation has no independent recovery copy and cannot restore to a known-good state " +
			"if the attacker also corrupts the live disk. To make matters worse, no Azure Monitor alert rules are configured, " +
			"so the snapshot-and-copy operation completes silently: the ARM activity log records the API call, but nobody is watching.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Insider or compromised identity",
				Action:    "Enumerate VM disks in the subscription and confirm they lack encryption.",
				Technical: "GET /subscriptions/{sub}/providers/Microsoft.Compute/disks?api-version=2023-10-02 - inspect encryptionSettings; disks show encryption.type='EncryptionAtRestWithPlatformKey' only (no customer key, no host-based encryption).",
				Technique: "T1580",
				EnabledBy: "zt_wl_020",
				Gain:      "Target list of unencrypted disks whose VHD content is readable if the raw blob is obtained.",
			},
			{
				Number:    2,
				Actor:     "Insider or compromised identity",
				Action:    "Create a snapshot of the target disk and grant access to generate a SAS URI for download.",
				Technical: "PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/snapshots/{name} with creationData.sourceResourceId pointing to the target disk; then POST .../beginGetAccess to produce a time-limited SAS URL for the snapshot blob.",
				Technique: "T1537",
				EnabledBy: "zt_wl_020",
				Gain:      "A downloadable copy of the entire disk volume as a VHD blob, accessible via a SAS URL.",
			},
			{
				Number:    3,
				Actor:     "Attacker (external infrastructure)",
				Action:    "Download the VHD snapshot to attacker-controlled infrastructure and mount it offline.",
				Technical: "azcopy copy 'https://{sa}.blob.core.windows.net/{container}/{snap}.vhd?{sas}' ./disk.vhd; mount locally via qemu-nbd or Hyper-V to browse the filesystem offline.",
				Technique: "T1530",
				EnabledBy: "zt_wl_020",
				Gain:      "Full offline access to every file, registry hive, credential cache, and database file on the disk.",
			},
			{
				Number:    4,
				Actor:     "Attacker (offline analysis)",
				Action:    "Extract credentials, application secrets, and sensitive data from the mounted volume.",
				Technical: "Parse SAM/SYSTEM/SECURITY hives for local credential hashes, extract connection strings from web.config and appsettings.json, recover database .mdf files, dump DPAPI master keys.",
				Technique: "T1005",
				EnabledBy: "zt_data_017",
				Gain:      "Plaintext credentials, application secrets, database contents, and PII extracted from the offline disk image.",
			},
			{
				Number:    5,
				Actor:     "Attacker",
				Action:    "Confirm no alerts fired and no backup exists to enable recovery or forensic comparison.",
				Technical: "No Azure Monitor alert rules are configured (zt_vis_012), so the Microsoft.Compute/snapshots/write activity log entry was never evaluated. No Azure Backup vault protects the VM (zt_data_017), so there is no independent recovery point to compare against or restore from.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_012",
				Gain:      "Complete operational stealth: the disk theft is recorded in the activity log but no human or automation is watching.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any identity with Disk Snapshot Contributor or equivalent on the target resource group.",
			LateralMovement:    "Offline credential extraction from the disk image provides passwords and tokens for lateral movement to other services.",
			MaxPrivilege:       "Depends on credentials found on the disk; commonly includes service account passwords, managed identity certificates, and database connection strings.",
			DataAtRisk:         []string{"VM filesystem contents", "Local credential caches (SAM/LSA)", "Application secrets and connection strings", "Database files", "Customer PII on disk"},
			ServicesAtRisk:     []string{"Virtual Machines", "Managed Disks", "Any service whose credentials are stored on the VM"},
			EstimatedScopePerc: "All VMs without disk encryption in the subscription",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "3.5.1", Impact: "Stored cardholder data is not rendered unreadable via strong cryptography; disk-level encryption is absent."},
			{Framework: "ISO 27001:2022", Control: "A.8.24", Impact: "Cryptographic controls are not applied to data at rest on virtual machine disks."},
			{Framework: "NIST 800-53", Control: "SC-28 / CP-9", Impact: "Protection of information at rest fails; backup policy is not enforced for recovery assurance."},
		},
		MinimalFixSet: []string{"zt_wl_020", "zt_vis_012"},
		PriorityFix: "Enable Azure Disk Encryption (ADE) or EncryptionAtHost on all VMs immediately - this renders snapshots useless without the KEK. " +
			"Then configure Azure Monitor alert rules on Microsoft.Compute/snapshots/write to detect future snapshot creation attempts.",
		BreakingNote: "Enabling ADE requires the VM to be restarted and needs Key Vault integration; schedule during a maintenance window. " +
			"EncryptionAtHost is transparent but requires a VM SKU that supports it.",
		MITRETechnique:    "T1537 / T1530",
		MITRETactic:       "Exfiltration / Collection",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-043: Firewall Threat Intel Bypass to C2
// ---------------------------------------------------------------------------

func buildChain043(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_net_012", "zt_net_018", "zt_vis_013")
	triggers := collectFindingIDs(findings, "zt_net_012", "zt_net_018", "zt_vis_013")

	return &models.AttackChain{
		ID:                 "CHAIN-043",
		Title:              "Firewall threat intel bypass to persistent C2 channel",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Azure Firewall is deployed but its threat intelligence mode is set to 'Alert only' instead of 'Deny', meaning known-malicious IPs and domains " +
			"generate a log entry but traffic is allowed through. An attacker who has initial access to any workload behind the firewall can establish " +
			"a command-and-control channel to known bad infrastructure and the firewall will wave it through with a warning nobody reads. " +
			"Meanwhile, the NSG on the workload subnets permits all outbound traffic (0.0.0.0/0), so even traffic that bypasses the firewall route " +
			"has no secondary control. The attacker exfiltrates data freely over HTTPS to a threat-intel-listed domain. " +
			"When the SOC eventually investigates, NSG flow logs have a retention of less than 90 days, so historical evidence of the C2 channel " +
			"and exfiltration volume has already been purged - the investigation hits a dead end.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker with workload access",
				Action:    "Establish an outbound C2 channel to a known-malicious domain or IP address.",
				Technical: "Implant beacons to a C2 framework (Cobalt Strike, Sliver) over HTTPS/443 to an IP listed in Microsoft's threat intelligence feed; Azure Firewall logs ThreatIntel=Alert but forwards the traffic.",
				Technique: "T1071.001",
				EnabledBy: "zt_net_012",
				Gain:      "Persistent, bidirectional command-and-control channel through the firewall.",
			},
			{
				Number:    2,
				Actor:     "Attacker with C2",
				Action:    "Confirm unrestricted outbound connectivity through the NSG for high-bandwidth exfiltration.",
				Technical: "NSG effective rules show outbound Allow to 0.0.0.0/0 on all ports; no service endpoints or Private Link force traffic through controlled paths; the attacker can reach any internet destination on any port.",
				Technique: "T1048.001",
				EnabledBy: "zt_net_018",
				Gain:      "Unlimited outbound bandwidth with no port or destination restrictions for data exfiltration.",
			},
			{
				Number:    3,
				Actor:     "Attacker with C2",
				Action:    "Stage and exfiltrate sensitive data over the established C2 channel using encrypted HTTPS.",
				Technical: "Compress and encrypt target data, then exfil via HTTPS POST to the C2 endpoint. TLS encryption prevents DPI even if the firewall were inspecting payloads. Volume is limited only by the VM's NIC bandwidth.",
				Technique: "T1041",
				EnabledBy: "zt_net_018",
				Gain:      "Bulk exfiltration of sensitive data to attacker infrastructure with no volume cap.",
			},
			{
				Number:    4,
				Actor:     "Attacker (anti-forensics)",
				Action:    "Wait for NSG flow log retention to expire, destroying network evidence of the C2 and exfiltration.",
				Technical: "NSG flow logs are configured with retention less than 90 days (zt_vis_013). After the retention window passes, the storage account auto-deletes the PT1H.json flow log blobs. The firewall threat intel alert log may persist longer but shows only 'Alert' actions, not deny - confirming the traffic was allowed.",
				Technique: "T1070.003",
				EnabledBy: "zt_vis_013",
				Gain:      "Forensic evidence of C2 traffic volume, destination IPs, and session durations is permanently destroyed.",
			},
			{
				Number:    5,
				Actor:     "SOC / IR team",
				Action:    "Investigate belatedly and find evidence gaps that prevent scope determination.",
				Technical: "Firewall logs show ThreatIntel alerts but no deny; NSG flow logs for the period have been purged; the investigation cannot determine exfiltration volume, full list of C2 destinations, or which workloads communicated externally.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_013",
				Gain:      "The attacker's operational history is unrecoverable, forcing the organisation to assume worst-case breach scope.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any compromised workload behind the Azure Firewall with outbound internet access.",
			LateralMovement:    "C2 channel enables the attacker to proxy tools inbound, pivot to other workloads, and stage further attacks from within the network.",
			MaxPrivilege:       "Depends on initial compromise; the chain enables persistent C2 and evidence destruction regardless of privilege level.",
			DataAtRisk:         []string{"Any data accessible to the compromised workload", "Credentials cached on the host", "Data from lateral movement targets"},
			ServicesAtRisk:     []string{"Azure Firewall (misconfigured)", "NSG-protected subnets", "All workloads routable through the firewall"},
			EstimatedScopePerc: "All subnets routed through the firewall with permissive NSG outbound rules",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "SI-4 / AU-11", Impact: "Network monitoring fails to block known threats; audit record retention is insufficient for investigation."},
			{Framework: "ISO 27001:2022", Control: "A.8.16 / A.8.15", Impact: "Network traffic monitoring does not deny known-malicious traffic; logging retention does not meet forensic needs."},
			{Framework: "SOC 2", Control: "CC7.2 / CC7.3", Impact: "The entity does not effectively monitor and respond to identified security events; evidence retention is insufficient."},
		},
		MinimalFixSet: []string{"zt_net_012", "zt_vis_013"},
		PriorityFix: "Switch Azure Firewall threat intelligence mode from 'Alert' to 'Deny' immediately - this kills active C2 channels to known-bad infrastructure in real time. " +
			"Then extend NSG flow log retention to at least 365 days to ensure forensic evidence survives.",
		BreakingNote: "Switching to Deny mode may block legitimate traffic to IPs that are false-positived in the threat intel feed. " +
			"Review the firewall's ThreatIntel alert logs for the past 30 days and whitelist any confirmed-legitimate destinations before flipping to Deny.",
		MITRETechnique:    "T1071.001 / T1048.001",
		MITRETactic:       "Command and Control / Exfiltration",
		KillChainPhase:    "Command & Control",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-044: Admin Credential Spray to Irrecoverable Tenant Lock
// ---------------------------------------------------------------------------

func buildChain044(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_014", "zt_id_023", "zt_id_012")
	triggers := collectFindingIDs(findings, "zt_id_014", "zt_id_023", "zt_id_012")

	return &models.AttackChain{
		ID:                 "CHAIN-044",
		Title:              "Admin credential spray to irrecoverable tenant lock",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Administrative accounts in this tenant do not require phishing-resistant authentication strength (FIDO2, certificate-based auth, or Windows Hello). " +
			"Simultaneously, users are not required to register for MFA, meaning many admin accounts have only a password as their sole credential. " +
			"An attacker conducts a low-and-slow password spray against the tenant's admin accounts, and because there is no authentication strength policy " +
			"demanding phishing-resistant factors, a correct password is enough to sign in. Once inside a Global Administrator account, " +
			"the attacker resets passwords for all other admins, disables their MFA registrations, and revokes their sessions. " +
			"The fatal final condition: no break-glass emergency access accounts exist. When the legitimate administrators are locked out, " +
			"there is no recovery path that does not involve a multi-week Microsoft support engagement. " +
			"The attacker has days of uncontested Global Admin access to exfiltrate data, create backdoor service principals, and destroy resources.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Enumerate valid admin account UPNs via tenant discovery and LinkedIn correlation.",
				Technical: "Probe login.microsoftonline.com/common/GetCredentialType with candidate UPNs to confirm account existence without triggering sign-in logs; cross-reference with LinkedIn to identify IT staff.",
				Technique: "T1589.002",
				EnabledBy: "zt_id_014",
				Gain:      "Validated list of admin account UPNs in the target tenant.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Execute a low-and-slow password spray against admin accounts, bypassing smart lockout thresholds.",
				Technical: "Spray one password per hour across all admin accounts from rotating residential proxies; no Conditional Access authentication strength policy blocks password-only auth, and no MFA registration means the accounts accept username+password alone.",
				Technique: "T1110.003",
				EnabledBy: "zt_id_023",
				Gain:      "Valid credentials for at least one Global Administrator account.",
			},
			{
				Number:    3,
				Actor:     "Attacker as Global Admin",
				Action:    "Reset credentials and revoke sessions for all other administrative accounts.",
				Technical: "POST /users/{id}/authentication/methods to overwrite phone/email MFA methods; POST /users/{id}/revokeSignInSessions; Reset-MsolPassword for each admin; disable per-user MFA registration.",
				Technique: "T1531",
				EnabledBy: "zt_id_012",
				Gain:      "All legitimate administrators are locked out of the tenant with no way to re-authenticate.",
			},
			{
				Number:    4,
				Actor:     "Attacker as sole Global Admin",
				Action:    "Confirm no break-glass accounts exist and establish persistent backdoor access.",
				Technical: "Enumerate all Global Admin role members; confirm no emergency access accounts with excluded Conditional Access policies exist (zt_id_012). Create a new service principal with Directory.ReadWrite.All and a 10-year client secret.",
				Technique: "T1136.003",
				EnabledBy: "zt_id_012",
				Gain:      "Sole, uncontested Global Administrator control with a persistent backdoor credential.",
			},
			{
				Number:    5,
				Actor:     "Attacker with tenant control",
				Action:    "Exfiltrate tenant data and optionally destroy resources to inflict maximum damage.",
				Technical: "Export all mailboxes via eDiscovery compliance search; export Azure subscriptions' Key Vault secrets; optionally delete resource groups and purge Key Vaults (if purge protection is off) to cause irrecoverable data loss.",
				Technique: "T1485",
				EnabledBy: "zt_id_014",
				Gain:      "Complete tenant compromise with no recovery path short of Microsoft support intervention taking days to weeks.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Password spray against admin accounts with no phishing-resistant MFA enforcement.",
			LateralMovement:    "Not required - Global Admin grants immediate access to all tenant resources and all Azure subscriptions.",
			MaxPrivilege:       "Global Administrator with exclusive control - all other admins locked out, no break-glass recovery.",
			DataAtRisk:         []string{"All Entra ID directory data", "All mailboxes and SharePoint content", "All Azure subscription resources", "Key Vault secrets across all subscriptions"},
			ServicesAtRisk:     []string{"Entra ID", "Exchange Online", "SharePoint", "Azure Resource Manager", "Key Vault", "All Azure services in linked subscriptions"},
			EstimatedScopePerc: "100% of the tenant and all linked subscriptions",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "8.3.1 / 8.4.2", Impact: "Multi-factor authentication is not enforced for administrative access to the cardholder data environment."},
			{Framework: "ISO 27001:2022", Control: "A.8.5 / A.5.16", Impact: "Secure authentication mechanisms are not applied to privileged accounts; identity management fails."},
			{Framework: "NIST 800-53", Control: "IA-2(1) / CP-2", Impact: "Multi-factor authentication for privileged accounts is absent; contingency planning (break-glass) does not exist."},
		},
		MinimalFixSet: []string{"zt_id_014", "zt_id_012"},
		PriorityFix: "Create two break-glass emergency access accounts immediately (cloud-only, excluded from Conditional Access, FIDO2 secured, monitored with alerts). " +
			"Then enforce an authentication strength policy requiring phishing-resistant MFA for all admin roles.",
		BreakingNote: "Enforcing phishing-resistant auth strength will block any admin who has not yet registered a FIDO2 key or certificate. " +
			"Distribute FIDO2 keys and confirm registration before enabling the policy. Break-glass account creation has no breaking impact.",
		MITRETechnique:    "T1110.003 / T1531",
		MITRETactic:       "Credential Access / Impact",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-045: Event Stream Hijack
// ---------------------------------------------------------------------------

func buildChain045(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_018", "zt_data_019", "zt_net_011")
	triggers := collectFindingIDs(findings, "zt_data_018", "zt_data_019", "zt_net_011")

	return &models.AttackChain{
		ID:                 "CHAIN-045",
		Title:              "Event stream hijack via public messaging services",
		Severity:           "HIGH",
		Likelihood:         "Low",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Event Hub namespaces are encrypted with Microsoft-managed keys only (no customer-managed key), meaning Microsoft - or anyone who compromises the platform key hierarchy - " +
			"can decrypt the data at rest. More critically, Service Bus namespaces are accessible from public networks, exposing queue and topic endpoints to the internet. " +
			"Without Azure Firewall deployed to provide network-level inspection and egress control, there is no choke point to detect or block an attacker " +
			"who enumerates the publicly-reachable Service Bus endpoint, obtains a valid SAS token (from a leaked connection string or a compromised workload), " +
			"and begins reading, injecting, or replaying messages in the event stream. " +
			"The attacker can silently eavesdrop on business events, inject malicious commands into processing pipelines, or replay financial transactions.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Discover publicly accessible Service Bus namespace endpoints via DNS enumeration.",
				Technical: "Enumerate *.servicebus.windows.net via DNS brute-force or certificate transparency logs; confirm TCP/443 (AMQP-over-WebSocket) and TCP/5671 (AMQP) are reachable from the internet.",
				Technique: "T1595.002",
				EnabledBy: "zt_data_019",
				Gain:      "Confirmed list of internet-reachable Service Bus namespaces belonging to the target.",
			},
			{
				Number:    2,
				Actor:     "External attacker",
				Action:    "Obtain a valid SAS token or connection string from a compromised workload or leaked configuration.",
				Technical: "Harvest connection strings from GitHub commits, Docker image layers, or environment variables on a compromised app service. SAS tokens often have long validity periods (years) and are not rotated.",
				Technique: "T1552.001",
				EnabledBy: "zt_net_011",
				Gain:      "Valid authentication credentials for the Service Bus namespace with Send/Listen/Manage rights.",
			},
			{
				Number:    3,
				Actor:     "Attacker with SAS token",
				Action:    "Eavesdrop on message queues and topics to intercept business-critical event data.",
				Technical: "Use Service Bus Explorer or custom AMQP client to peek/receive messages from queues and subscriptions; messages may contain PII, financial transactions, or internal commands.",
				Technique: "T1040",
				EnabledBy: "zt_data_019",
				Gain:      "Real-time visibility into all event data flowing through the compromised namespace.",
			},
			{
				Number:    4,
				Actor:     "Attacker with SAS token",
				Action:    "Inject malicious messages into processing queues to manipulate downstream business logic.",
				Technical: "Send crafted messages to queues consumed by order processing, payment, or workflow automation systems; lack of message signing means consumers cannot distinguish legitimate from injected messages.",
				Technique: "T1565.002",
				EnabledBy: "zt_data_018",
				Gain:      "Ability to trigger arbitrary business actions: fraudulent transactions, workflow manipulation, or denial of service via poison messages.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Publicly accessible Service Bus namespace with a leaked or stolen SAS token.",
			LateralMovement:    "Message injection can trigger downstream services to take actions that extend the attacker's reach (e.g., provisioning resources, modifying data).",
			MaxPrivilege:       "Full read/write/manage access to the messaging namespace; downstream impact depends on what consumers do with the messages.",
			DataAtRisk:         []string{"Event stream payloads (PII, financial data, internal commands)", "Event Hub capture data at rest (platform-key only)", "Downstream data stores populated by stream consumers"},
			ServicesAtRisk:     []string{"Event Hubs", "Service Bus", "Downstream consumers (Functions, Logic Apps, custom processors)"},
			EstimatedScopePerc: "All queues and topics in the affected namespaces",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "4.2.1 / 3.5.1", Impact: "Sensitive data in transit through messaging services is not protected with customer-controlled cryptography; data at rest uses only platform-managed keys."},
			{Framework: "ISO 27001:2022", Control: "A.8.20 / A.8.24", Impact: "Network security for messaging services is not enforced; cryptographic controls over data in transit and at rest are insufficient."},
			{Framework: "SOC 2", Control: "CC6.1 / CC6.6", Impact: "Logical access controls over messaging infrastructure are insufficient; network boundary controls do not restrict public access."},
		},
		MinimalFixSet: []string{"zt_data_019", "zt_net_011"},
		PriorityFix: "Disable public network access on Service Bus namespaces and configure Private Endpoints immediately - this kills internet-based access even with a valid SAS token. " +
			"Then deploy or configure Azure Firewall to provide egress inspection for workloads that need to reach the messaging tier.",
		BreakingNote: "Disabling public access on Service Bus will break any external client or SaaS integration that connects over the internet. " +
			"Inventory all producers and consumers and migrate them to Private Endpoint connectivity or VNet integration before applying the restriction.",
		MITRETechnique:    "T1040 / T1565.002",
		MITRETactic:       "Collection / Impact",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-046: Function App Compromise to Internal Network Pivot
// ---------------------------------------------------------------------------

func buildChain046(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_017", "zt_id_025", "zt_net_019")
	triggers := collectFindingIDs(findings, "zt_wl_017", "zt_id_025", "zt_net_019")

	return &models.AttackChain{
		ID:                 "CHAIN-046",
		Title:              "Function App compromise to internal network pivot",
		Severity:           "HIGH",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An Azure Function App runs on an outdated runtime version with known CVEs, creating a remotely exploitable entry point. " +
			"Rather than using a managed identity for authentication to downstream services, the Function stores connection strings and service principal credentials " +
			"in application settings (environment variables), making them trivially extractable after code execution is achieved. " +
			"The Function is VNet-integrated into a subnet that has no Network Security Group, meaning once the attacker has the Function's network context, " +
			"they can reach any host on the subnet - and any peered VNet - without any network-layer access control. " +
			"The combination turns a single serverless function exploit into a full internal network compromise.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Exploit a known vulnerability in the outdated Function App runtime to achieve remote code execution.",
				Technical: "The Function runs on a runtime version with published CVEs (e.g., Node.js <18 LTS, Python 3.8 EOL, .NET 6 out of support). Attacker sends a crafted HTTP request that triggers the vulnerability in the runtime or a dependent package.",
				Technique: "T1190",
				EnabledBy: "zt_wl_017",
				Gain:      "Arbitrary code execution within the Function App's sandbox context.",
			},
			{
				Number:    2,
				Actor:     "Attacker with code execution",
				Action:    "Dump application settings to extract stored credentials and connection strings.",
				Technical: "Read environment variables via process.env (Node), os.environ (Python), or Environment.GetEnvironmentVariables() (.NET). Application settings contain SQL connection strings, storage account keys, and service principal clientId/clientSecret pairs because managed identity is not used.",
				Technique: "T1552.001",
				EnabledBy: "zt_id_025",
				Gain:      "Plaintext credentials for downstream Azure services: SQL, Storage, Key Vault, and potentially a service principal with broad RBAC.",
			},
			{
				Number:    3,
				Actor:     "Attacker with stolen credentials",
				Action:    "Use the service principal credentials to authenticate to Azure Resource Manager and enumerate the environment.",
				Technical: "az login --service-principal -u {clientId} -p {clientSecret} --tenant {tenantId}; az resource list; the SP typically has Contributor at the resource group level or broader.",
				Technique: "T1078.004",
				EnabledBy: "zt_id_025",
				Gain:      "Authenticated ARM access with whatever RBAC the stolen service principal holds.",
			},
			{
				Number:    4,
				Actor:     "Attacker with network access",
				Action:    "Pivot from the Function's VNet-integrated subnet to internal hosts on the unprotected subnet and peered VNets.",
				Technical: "The Function's outbound traffic originates from the integrated subnet which has no NSG. Scan internal IP ranges with nmap/portscan from within the Function execution context; reach databases, VMs, and internal APIs on RFC1918 addresses with zero network filtering.",
				Technique: "T1046",
				EnabledBy: "zt_net_019",
				Gain:      "Network-level access to all hosts on the subnet and any peered VNets, bypassing what should be the network segmentation boundary.",
			},
			{
				Number:    5,
				Actor:     "Attacker on internal network",
				Action:    "Access internal databases and services using the stolen connection strings from the Function's environment.",
				Technical: "Connect to SQL databases, Redis caches, and storage accounts using the connection strings harvested in Step 2; these services trust connections from the VNet and the credentials are valid.",
				Technique: "T1021.002",
				EnabledBy: "zt_net_019",
				Gain:      "Full access to internal data stores and services that were assumed to be protected by network isolation.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Publicly accessible Function App running an outdated, vulnerable runtime version.",
			LateralMovement:    "VNet integration with no NSG allows unrestricted lateral movement to all hosts on the subnet and peered networks.",
			MaxPrivilege:       "Service principal credentials from the Function's environment, plus network access to all internal hosts.",
			DataAtRisk:         []string{"Function App application secrets", "SQL databases reachable from the subnet", "Storage accounts with harvested keys", "Internal APIs and services on peered VNets"},
			ServicesAtRisk:     []string{"Azure Functions", "SQL Database", "Storage Accounts", "Redis Cache", "Any service on the integrated VNet"},
			EstimatedScopePerc: "The integrated subnet and all peered VNets",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "6.3.2 / 1.3.2", Impact: "Known security vulnerabilities are not patched; network segmentation does not restrict traffic between application tiers."},
			{Framework: "ISO 27001:2022", Control: "A.8.8 / A.8.22", Impact: "Technical vulnerability management fails; network segregation controls are not applied to the serverless workload subnet."},
			{Framework: "NIST 800-53", Control: "SI-2 / SC-7", Impact: "Flaw remediation is not timely; boundary protection between network zones does not exist."},
		},
		MinimalFixSet: []string{"zt_wl_017", "zt_net_019"},
		PriorityFix: "Update the Function App runtime to the latest supported LTS version to close the RCE vector. " +
			"Then apply an NSG to the VNet-integrated subnet with deny-all-inbound and explicit allow rules for required traffic only.",
		BreakingNote: "Runtime upgrades may introduce breaking API changes in the Function's dependencies; test thoroughly in a staging slot before swapping. " +
			"NSG application to the subnet will block any traffic not explicitly allowed - audit existing traffic patterns with NSG flow logs before enforcement.",
		MITRETechnique:    "T1190 / T1552.001",
		MITRETactic:       "Initial Access / Lateral Movement",
		KillChainPhase:    "Exploitation",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-047: NSG Flow Log Evidence Destruction
// ---------------------------------------------------------------------------

func buildChain047(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_vis_013", "zt_net_019", "zt_vis_016")
	triggers := collectFindingIDs(findings, "zt_vis_013", "zt_net_019", "zt_vis_016")

	return &models.AttackChain{
		ID:                 "CHAIN-047",
		Title:              "NSG flow log evidence destruction via retention and logging gaps",
		Severity:           "MEDIUM",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "An attacker operating inside the network benefits from a triple visibility gap. First, subnets with no NSG applied generate no flow logs at all, " +
			"giving the attacker network segments where their traffic is completely invisible to network forensics. " +
			"Second, where NSGs do exist, flow log retention is set below 90 days, meaning evidence of the attacker's network activity is automatically purged " +
			"well before most organisations detect a breach (industry average: 200+ days). " +
			"Third, storage account diagnostic logging is disabled, so even if the attacker accesses storage accounts to stage or exfiltrate data, " +
			"there is no record of the read/write/delete operations. The net result: the attacker can operate across unmonitored subnets, " +
			"wait for flow logs to age out, and access storage with impunity - leaving the IR team with virtually no network or data-access forensics.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Attacker with internal access",
				Action:    "Identify subnets with no NSG applied and route lateral movement through them.",
				Technical: "Enumerate subnet configurations via ARM API or from within the network; subnets without an associated NSG produce no flow log records. All TCP/UDP traffic traversing these subnets is invisible to network monitoring.",
				Technique: "T1562.008",
				EnabledBy: "zt_net_019",
				Gain:      "Network transit paths where all traffic is unlogged and forensically invisible.",
			},
			{
				Number:    2,
				Actor:     "Attacker with internal access",
				Action:    "Perform reconnaissance and lateral movement across unprotected subnets to reach high-value targets.",
				Technical: "Port scan, credential relay, and service exploitation across the NSG-free subnets; no flow log captures source/destination IPs, ports, or byte counts for this traffic.",
				Technique: "T1046",
				EnabledBy: "zt_net_019",
				Gain:      "Access to targets reachable from the unprotected subnets without generating any network telemetry.",
			},
			{
				Number:    3,
				Actor:     "Attacker",
				Action:    "Access storage accounts to stage exfiltration or read sensitive blobs, knowing diagnostic logging is off.",
				Technical: "Storage account diagnostic logging (StorageRead, StorageWrite, StorageDelete) is disabled (zt_vis_016); the attacker's blob downloads, container enumerations, and file deletions produce no log entries in the storage analytics or diagnostic settings.",
				Technique: "T1530",
				EnabledBy: "zt_vis_016",
				Gain:      "Undetectable access to storage account data - no record of what was read, written, or deleted.",
			},
			{
				Number:    4,
				Actor:     "Time (passive)",
				Action:    "NSG flow log retention expires, automatically purging network evidence from monitored subnets.",
				Technical: "Flow logs configured with retentionPolicy.days < 90 auto-delete the PT1H.json blobs from the flow log storage account. The attacker does not need to actively delete evidence - the retention policy does it for them.",
				Technique: "T1070.003",
				EnabledBy: "zt_vis_013",
				Gain:      "Network forensic evidence for the monitored subnets is permanently destroyed by the system's own retention policy.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any foothold on the internal network, particularly in subnets without NSGs.",
			LateralMovement:    "Unrestricted within NSG-free subnets; movement through monitored subnets is logged but evidence is short-lived.",
			MaxPrivilege:       "Determined by the attacker's credential access; the chain amplifies stealth, not privilege.",
			DataAtRisk:         []string{"Storage account contents (access unlogged)", "Any data reachable from unmonitored subnets", "Forensic evidence itself (destroyed by retention)"},
			ServicesAtRisk:     []string{"Network Security Groups (absent)", "NSG Flow Logs (under-retained)", "Storage Accounts (unlogged)"},
			EstimatedScopePerc: "All subnets without NSGs plus all storage accounts without diagnostic logging",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "AU-11 / AU-6", Impact: "Audit record retention does not meet minimum periods for forensic investigation; audit review and analysis capabilities are degraded."},
			{Framework: "ISO 27001:2022", Control: "A.8.15 / A.8.16", Impact: "Logging and monitoring of network activity is incomplete; event log retention does not support incident investigation."},
			{Framework: "PCI DSS 4.0", Control: "10.7.1", Impact: "Audit log history is not retained for at least 12 months, with at least 3 months immediately available for analysis."},
		},
		MinimalFixSet: []string{"zt_net_019", "zt_vis_013"},
		PriorityFix: "Apply NSGs to all subnets immediately to establish network segmentation and enable flow logging. " +
			"Then extend flow log retention to at least 365 days and enable storage account diagnostic logging (StorageRead, StorageWrite, StorageDelete).",
		BreakingNote: "Applying NSGs to subnets that currently have none will enforce default-deny for inbound traffic from other subnets. " +
			"Audit existing traffic patterns (if any flow logs exist from upstream NSGs) and create explicit allow rules for legitimate traffic before applying.",
		MITRETechnique:    "T1562.008 / T1070.003",
		MITRETactic:       "Defense Evasion",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-048: Cosmos DB to Cross-Service Data Theft
// ---------------------------------------------------------------------------

func buildChain048(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_data_011", "zt_vis_014", "zt_data_014")
	triggers := collectFindingIDs(findings, "zt_data_011", "zt_vis_014", "zt_data_014")

	return &models.AttackChain{
		ID:                 "CHAIN-048",
		Title:              "Cosmos DB to cross-service data theft and evidence destruction",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "A Cosmos DB account is configured to accept connections from all networks, including the public internet. An attacker who obtains " +
			"the account's primary key (from a leaked connection string, a compromised app, or an over-privileged identity) can connect directly " +
			"from anywhere in the world and read every database and collection in the account. " +
			"Cosmos DB connection strings frequently contain or reference Key Vault secret URIs for downstream services. " +
			"The attacker follows these references to a Key Vault that has diagnostic logging disabled, meaning secret access operations are invisible. " +
			"Worse, the Key Vault has purge protection disabled, so the attacker can permanently delete secrets and keys to destroy evidence " +
			"and cause operational damage. The result is a cross-service attack: Cosmos DB is the entry, Key Vault is the pivot, " +
			"and the combination of no logging and no purge protection means the attacker can steal everything and burn the evidence behind them.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Connect to the Cosmos DB account from the public internet using a stolen primary key.",
				Technical: "Cosmos DB firewall is set to 'All networks' (isVirtualNetworkFilterEnabled=false, ipRangeFilter empty). Attacker uses the Azure Cosmos DB SDK or REST API with the primary key from a leaked connection string to enumerate databases and collections.",
				Technique: "T1078.004",
				EnabledBy: "zt_data_011",
				Gain:      "Full read/write access to every database, collection, and document in the Cosmos DB account.",
			},
			{
				Number:    2,
				Actor:     "Attacker with Cosmos DB access",
				Action:    "Exfiltrate all documents from high-value collections containing PII, financial records, or application state.",
				Technical: "Execute cross-partition queries with no RU limit; use the change feed to stream all historical and real-time changes; export via SELECT * FROM c across all containers.",
				Technique: "T1530",
				EnabledBy: "zt_data_011",
				Gain:      "Complete database exfiltration including customer PII, transaction records, and application configuration documents.",
			},
			{
				Number:    3,
				Actor:     "Attacker with Cosmos DB access",
				Action:    "Extract Key Vault references from Cosmos DB configuration documents and application settings.",
				Technical: "Application documents and Cosmos DB stored procedures often contain Key Vault secret URIs (@Microsoft.KeyVault(SecretUri=...)) or direct references to vault names and secret names used by the application tier.",
				Technique: "T1552.001",
				EnabledBy: "zt_vis_014",
				Gain:      "Knowledge of Key Vault names, secret names, and the relationship between Cosmos DB and the Key Vault tier.",
			},
			{
				Number:    4,
				Actor:     "Attacker with Key Vault access",
				Action:    "Access the Key Vault to steal secrets, certificates, and keys with no diagnostic trail.",
				Technical: "Using credentials obtained from Cosmos DB or the original compromised identity, GET /secrets, /keys, /certificates from the Key Vault. Diagnostic logging is disabled (zt_vis_014), so SecretGet, KeySign, and CertificateGet operations produce no audit log entries.",
				Technique: "T1555.006",
				EnabledBy: "zt_vis_014",
				Gain:      "All secrets, keys, and certificates from the Key Vault - completely undetected due to missing diagnostic logs.",
			},
			{
				Number:    5,
				Actor:     "Attacker covering tracks",
				Action:    "Purge Key Vault secrets and keys to destroy evidence and cause operational damage.",
				Technical: "DELETE /secrets/{name} followed by POST /deletedsecrets/{name}/purge - because purge protection is disabled (zt_data_014), the soft-deleted secret is permanently destroyed with no recovery path. This eliminates evidence of what was stored and breaks dependent applications.",
				Technique: "T1485",
				EnabledBy: "zt_data_014",
				Gain:      "Permanent destruction of Key Vault contents: evidence eliminated, dependent applications broken, no recovery possible.",
			},
			{
				Number:    6,
				Actor:     "Attacker",
				Action:    "Use stolen Key Vault secrets to access additional services (SQL, Storage, third-party APIs) for maximum blast radius.",
				Technical: "Key Vault secrets typically include SQL connection strings, storage account keys, API keys for third-party services, and TLS certificates. Each secret unlocks another service in the architecture.",
				Technique: "T1552.004",
				EnabledBy: "zt_data_014",
				Gain:      "Cascading access to every service whose credentials were stored in the compromised Key Vault.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Publicly accessible Cosmos DB account with a leaked primary key.",
			LateralMovement:    "Cosmos DB → Key Vault → every service whose credentials are stored in the vault (SQL, Storage, third-party APIs).",
			MaxPrivilege:       "Full read/write on Cosmos DB, full secret/key/certificate access on Key Vault, cascading access to downstream services.",
			DataAtRisk:         []string{"All Cosmos DB documents", "All Key Vault secrets and certificates", "SQL databases (via stolen connection strings)", "Storage accounts (via stolen keys)", "Third-party service data (via stolen API keys)"},
			ServicesAtRisk:     []string{"Cosmos DB", "Key Vault", "SQL Database", "Storage Accounts", "Any third-party service with keys in the vault"},
			EstimatedScopePerc: "Cosmos DB account + Key Vault + all downstream services referenced by vault secrets",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "3.5.1 / 10.2.1", Impact: "Data stores accessible from public networks without compensating controls; audit logs for secret access are absent."},
			{Framework: "ISO 27001:2022", Control: "A.8.11 / A.8.10", Impact: "Data masking and network isolation for databases are not applied; cryptographic key management lacks audit trail."},
			{Framework: "NIST 800-53", Control: "SC-7 / AU-2", Impact: "Boundary protection for database services fails; auditable events for secret access are not logged."},
		},
		MinimalFixSet: []string{"zt_data_011", "zt_data_014"},
		PriorityFix: "Restrict Cosmos DB network access to selected VNets and Private Endpoints immediately - this blocks public internet access even with a valid key. " +
			"Then enable purge protection on all Key Vaults (this is irreversible and cannot be disabled once set, which is the point).",
		BreakingNote: "Restricting Cosmos DB to VNet/Private Endpoint access will break any application connecting from outside the VNet (e.g., local developer machines, external SaaS connectors). " +
			"Ensure all application tiers are VNet-integrated or use Private Endpoints before restricting. Enabling purge protection is permanent and cannot be reversed.",
		MITRETechnique:    "T1530 / T1485",
		MITRETactic:       "Collection / Impact",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-049: AKS Full Stack Compromise
// ---------------------------------------------------------------------------

func buildChain049(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_wl_013", "zt_wl_012", "zt_wl_014", "zt_wl_015", "zt_wl_016", "zt_wl_021")
	triggers := collectFindingIDs(findings, "zt_wl_013", "zt_wl_012", "zt_wl_014", "zt_wl_015", "zt_wl_016", "zt_wl_021")

	return &models.AttackChain{
		ID:                 "CHAIN-049",
		Title:              "AKS full stack compromise via public registry and layered misconfigurations",
		Severity:           "CRITICAL",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "This is the Kubernetes nightmare scenario where every layer of the stack is misconfigured simultaneously. " +
			"The Azure Container Registry allows public (anonymous) access, serving as the anchor finding that enables supply-chain injection. " +
			"On top of that, one or more of the following conditions amplify the blast radius: ACR admin account is enabled (providing a static, non-rotatable credential), " +
			"AKS has no network policy enforcement (pods can communicate freely across namespaces), Azure RBAC for Kubernetes is not enabled " +
			"(legacy kubeconfig grants cluster-admin), pod security standards are not enforced (privileged pods can escape to the node), " +
			"and Microsoft Defender for Containers is not enabled (runtime threats go undetected). " +
			"An attacker who pushes a malicious image to the public ACR can escalate through whichever combination of these weaknesses exists, " +
			"ultimately achieving cluster-admin, node-level access, and control-plane compromise of the entire AKS environment.",
		TriggerFindings: triggers,
		TriggerLogic:    "ANCHOR_PLUS_ONE",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Supply-chain attacker",
				Action:    "Push a malicious container image to the publicly accessible ACR, optionally using the admin credential.",
				Technical: "ACR is configured with publicNetworkAccess=Enabled and anonymousPullEnabled=true (zt_wl_013). If the admin account is enabled (zt_wl_012), the attacker may also use the static admin username/password (available via az acr credential show) to push. Image tag 'latest' or a version tag is overwritten with a trojanised image.",
				Technique: "T1195.002",
				EnabledBy: "zt_wl_013",
				Gain:      "Malicious image placed at a trusted tag in the production registry.",
			},
			{
				Number:    2,
				Actor:     "AKS cluster (automated pull)",
				Action:    "Pull and deploy the tainted image as a privileged pod due to missing pod security enforcement.",
				Technical: "No pod security standards (zt_wl_016) means the malicious image's pod spec can request privileged=true, hostPID=true, hostNetwork=true, and mount hostPath=/. The Kubernetes admission controller does not reject the escalated pod spec.",
				Technique: "T1610",
				EnabledBy: "zt_wl_016",
				Gain:      "Malicious container running with full host privileges inside the AKS cluster.",
			},
			{
				Number:    3,
				Actor:     "Attacker in privileged pod",
				Action:    "Escape the container to the underlying node and steal the kubelet's managed identity token.",
				Technical: "Mount the host filesystem via hostPath=/, access /var/lib/kubelet and the container runtime socket. Query IMDS at 169.254.169.254 from the host network namespace to obtain the node's managed identity token.",
				Technique: "T1611",
				EnabledBy: "zt_wl_016",
				Gain:      "Root access on the AKS node and a valid ARM token for the node's managed identity.",
			},
			{
				Number:    4,
				Actor:     "Attacker on node",
				Action:    "Move laterally across namespaces exploiting the absence of network policies.",
				Technical: "No Kubernetes network policies (zt_wl_014) means all pod-to-pod traffic is allowed across every namespace. The attacker's pod can reach kube-system components, monitoring agents, and every application pod's exposed ports directly.",
				Technique: "T1210",
				EnabledBy: "zt_wl_014",
				Gain:      "Unrestricted network access to every pod and service in every namespace of the cluster.",
			},
			{
				Number:    5,
				Actor:     "Attacker with cluster access",
				Action:    "Obtain cluster-admin privileges via legacy kubeconfig because Azure RBAC for Kubernetes is disabled.",
				Technical: "Without Azure RBAC for AKS (zt_wl_015), the cluster uses legacy Kubernetes RBAC. The attacker extracts the cluster-admin kubeconfig from the compromised node or from the AKS management API using the stolen managed identity token (az aks get-credentials --admin).",
				Technique: "T1078.001",
				EnabledBy: "zt_wl_015",
				Gain:      "Full cluster-admin Kubernetes API access - can create, modify, and delete any resource in any namespace.",
			},
			{
				Number:    6,
				Actor:     "Attacker with cluster-admin",
				Action:    "Operate with impunity as Defender for Containers is not monitoring runtime threats.",
				Technical: "Microsoft Defender for Containers (zt_wl_021) is not enabled, so runtime threat detections (crypto mining, reverse shells, suspicious exec into containers, known malicious images) are not generated. The attacker's activities produce no security alerts.",
				Technique: "T1562.001",
				EnabledBy: "zt_wl_021",
				Gain:      "Complete AKS stack compromise with no runtime detection: registry to pod to node to cluster-admin, entirely unmonitored.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Publicly accessible Azure Container Registry allowing anonymous image push.",
			LateralMovement:    "Container → privileged pod → node → cross-namespace (no network policy) → cluster-admin (no Azure RBAC).",
			MaxPrivilege:       "cluster-admin on AKS + node-level managed identity on ARM + potential access to all downstream services the cluster identity can reach.",
			DataAtRisk:         []string{"All application data accessible to cluster workloads", "Kubernetes Secrets (including TLS certs and service credentials)", "Persistent Volumes and their contents", "Container registry images (IP, source code)"},
			ServicesAtRisk:     []string{"AKS", "ACR", "Resource Manager (via node identity)", "All services consumed by cluster workloads"},
			EstimatedScopePerc: "100% of the AKS cluster and its resource group",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "NIST 800-53", Control: "SA-12 / AC-6 / SI-4", Impact: "Supply chain integrity fails; least privilege is not enforced in the container platform; continuous monitoring is absent."},
			{Framework: "ISO 27001:2022", Control: "A.5.19 / A.8.2 / A.8.22", Impact: "Supplier security controls are missing; privileged access rights are not managed; network segmentation within the cluster is absent."},
			{Framework: "PCI DSS 4.0", Control: "6.3 / 7.2.1 / 11.5", Impact: "Secure development practices not applied to container images; access control not enforced; intrusion detection is absent."},
		},
		MinimalFixSet: []string{"zt_wl_013", "zt_wl_016"},
		PriorityFix: "Disable anonymous access on the ACR and enable pod security standards (Restricted profile) on AKS immediately. " +
			"These two fixes break the chain at both entry (supply chain) and escalation (container escape). " +
			"Then enable Azure RBAC for Kubernetes, apply network policies, disable the ACR admin account, and enable Defender for Containers.",
		BreakingNote: "Disabling ACR anonymous access breaks any external consumer pulling without authentication. " +
			"Enforcing Restricted pod security will reject pods with privileged, hostPath, hostNetwork, or hostPID settings - audit existing workloads with --dry-run=server before enforcement.",
		MITRETechnique:    "T1195.002 / T1611 / T1078.001",
		MITRETactic:       "Initial Access / Privilege Escalation / Defense Evasion",
		KillChainPhase:    "Delivery",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-050: Defender Notification Black Hole
// ---------------------------------------------------------------------------

func buildChain050(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_vis_020", "zt_vis_012", "zt_vis_018")
	triggers := collectFindingIDs(findings, "zt_vis_020", "zt_vis_012", "zt_vis_018")

	return &models.AttackChain{
		ID:                 "CHAIN-050",
		Title:              "Defender notification black hole - detections without response",
		Severity:           "HIGH",
		Likelihood:         "High",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Microsoft Defender for Cloud is generating security alerts, but nobody is listening. " +
			"Email notifications for Defender alerts are not configured, so high-severity detections like 'Suspicious login to VM', " +
			"'Crypto mining activity detected', or 'Mass secret access from Key Vault' sit unread in the Azure portal. " +
			"No Azure Monitor alert rules are configured to catch activity log events (resource deletions, role assignments, policy changes), " +
			"so control-plane abuse generates no notification. And no Action Groups are defined, meaning even if someone were to create an alert rule, " +
			"there is no delivery mechanism (email, SMS, webhook, ITSM ticket) to route it to a human. " +
			"The practical effect: the organisation is paying for Defender's detection engine but has zero response capability. " +
			"Every detection rots in the portal, and attackers operate with unlimited dwell time because no one is ever told to look.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "Any attacker (any TTP)",
				Action:    "Trigger a Defender for Cloud alert through malicious activity that Defender is designed to detect.",
				Technical: "Defender detects activity such as T1110 (brute force), T1496 (crypto mining), T1555.006 (Key Vault secret mass-read), or T1078.004 (suspicious cloud identity use). An alert is generated with severity High or Critical and stored in the SecurityAlert table.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_020",
				Gain:      "The attack is detected by Defender, but the detection has no delivery path to a human responder.",
			},
			{
				Number:    2,
				Actor:     "System (no action)",
				Action:    "Defender attempts to send email notification but no recipients are configured.",
				Technical: "Security Center email notification settings (zt_vis_020) have no email addresses configured. The 'Send email notification for high severity alerts' toggle may be on, but with no recipients, the notification is silently discarded.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_020",
				Gain:      "High and critical severity Defender alerts accumulate in the portal with no email delivery.",
			},
			{
				Number:    3,
				Actor:     "System (no action)",
				Action:    "Activity log events (resource modifications, role changes, policy updates) occur without triggering any alert rule.",
				Technical: "No Azure Monitor alert rules are configured (zt_vis_012). Administrative operations like Microsoft.Authorization/roleAssignments/write, Microsoft.Resources/subscriptions/resourceGroups/delete, and Microsoft.KeyVault/vaults/secrets/getSecret generate activity log entries but no alert evaluation occurs.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_012",
				Gain:      "Control-plane abuse is logged but never evaluated against alert conditions - no notification is possible.",
			},
			{
				Number:    4,
				Actor:     "System (no action)",
				Action:    "Even manual alert rule creation would fail to notify because no Action Groups exist as delivery endpoints.",
				Technical: "No Azure Monitor Action Groups are configured (zt_vis_018). Action Groups are the sole mechanism for delivering notifications (email, SMS, webhook, Logic App, ITSM) from Azure Monitor. Without them, the notification pipeline has no terminus.",
				Technique: "T1562.008",
				EnabledBy: "zt_vis_018",
				Gain:      "The entire Azure notification infrastructure is non-functional: detection exists, but the delivery chain is broken at every link.",
			},
			{
				Number:    5,
				Actor:     "Attacker (unrestricted dwell)",
				Action:    "Operate with unlimited dwell time, escalate privileges, exfiltrate data, and establish persistence without time pressure.",
				Technical: "With no notification reaching any human, the attacker's dwell time is bounded only by when someone happens to log into the Azure portal and navigate to Defender alerts. Industry data shows unnotified breaches average 200+ days before detection. The attacker has months to achieve objectives.",
				Technique: "T1078.004",
				EnabledBy: "zt_vis_012",
				Gain:      "Months of undetected access to escalate, pivot, exfiltrate, and establish durable persistence.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Any attack vector - this chain amplifies all others by eliminating the notification response loop.",
			LateralMovement:    "Unlimited - the attacker is never interrupted because no one is notified of Defender detections.",
			MaxPrivilege:       "Whatever the attacker can achieve given unlimited, undetected dwell time.",
			DataAtRisk:         []string{"All data in the subscription", "The scope depends entirely on the undetected attack's progression"},
			ServicesAtRisk:     []string{"Microsoft Defender for Cloud (detections wasted)", "Azure Monitor (no alert rules)", "All Azure services (unmonitored)"},
			EstimatedScopePerc: "100% of all subscriptions in the Defender scope",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "10.7.2 / 12.10.1", Impact: "Failures of critical security control systems are not detected and responded to promptly; incident response plan cannot execute without notification."},
			{Framework: "ISO 27001:2022", Control: "A.5.24 / A.5.25", Impact: "Information security incident management planning and response processes fail when detections do not reach responders."},
			{Framework: "SOC 2", Control: "CC7.3 / CC7.4", Impact: "The entity does not respond to identified security incidents in a timely manner; the communication of incidents is not functional."},
		},
		MinimalFixSet: []string{"zt_vis_020", "zt_vis_018"},
		PriorityFix: "Configure Defender email notifications with the security team's distribution list and enable high-severity alert emails immediately. " +
			"Create an Action Group with email, SMS, and webhook (ITSM/Slack/Teams) endpoints, then create alert rules for critical activity log operations.",
		BreakingNote: "No breaking impact - these are purely additive configurations. The only risk is alert fatigue if thresholds are set too low. " +
			"Start with High and Critical severity only, then tune down to Medium once the team has established a triage rhythm.",
		MITRETechnique:    "T1562.008",
		MITRETactic:       "Defense Evasion",
		KillChainPhase:    "Actions on Objectives",
		AffectedResources: resources,
	}
}

// ---------------------------------------------------------------------------
// CHAIN-051: Token Replay to Persistent Backdoor
// ---------------------------------------------------------------------------

func buildChain051(findings map[string][]models.Finding, snapshot *models.AzureSnapshot) *models.AttackChain {
	resources := extractResourceIDs(findings, "zt_id_019", "zt_id_014", "zt_vis_017")
	triggers := collectFindingIDs(findings, "zt_id_019", "zt_id_014", "zt_vis_017")

	return &models.AttackChain{
		ID:                 "CHAIN-051",
		Title:              "Token replay to persistent backdoor via unmonitored admin session",
		Severity:           "CRITICAL",
		Likelihood:         "Medium",
		EnvironmentSummary: envSummary(resources),
		Narrative: "Entra ID token lifetime policies are configured with extended access token lifetimes (or the default 1-hour refresh cycle is not paired with " +
			"Continuous Access Evaluation), giving stolen tokens a long window of usability. Administrative accounts do not require phishing-resistant " +
			"authentication strength, so an attacker who intercepts or steals a token (via AiTM phishing, a compromised device, or a session hijack) " +
			"faces no step-up authentication challenge when performing sensitive administrative operations. " +
			"The attacker uses the long-lived admin token to create a backdoor service principal, add federation trust to an external IdP, " +
			"or register a new Global Admin - all operations that establish persistence beyond the lifetime of the stolen token. " +
			"Because the Activity Log is not exported to a Log Analytics Workspace or Storage Account, the administrative operations " +
			"that established persistence are retained for only 90 days in the built-in Activity Log and are not queryable by SIEM or automation. " +
			"By the time the breach is discovered months later, the evidence of how persistence was established has been purged.",
		TriggerFindings: triggers,
		TriggerLogic:    "ALL",
		Steps: []models.ChainStep{
			{
				Number:    1,
				Actor:     "External attacker",
				Action:    "Steal an admin user's access token via adversary-in-the-middle (AiTM) phishing or a compromised endpoint.",
				Technical: "Deploy an AiTM phishing proxy (Evilginx2, Modlishka) targeting the tenant's login page. The proxy captures the session cookie and access token after the user authenticates. Long token lifetime (zt_id_019) means the captured token remains valid for an extended period without requiring re-authentication.",
				Technique: "T1557.003",
				EnabledBy: "zt_id_019",
				Gain:      "A valid, long-lived access token for an administrative account.",
			},
			{
				Number:    2,
				Actor:     "Attacker with admin token",
				Action:    "Use the stolen token to perform administrative operations without encountering step-up authentication.",
				Technical: "No authentication strength policy (zt_id_014) requires phishing-resistant MFA for admin operations. The stolen token (obtained via AiTM, bypassing standard MFA) is accepted for sensitive operations: role assignments, app registrations, and directory modifications.",
				Technique: "T1550.001",
				EnabledBy: "zt_id_014",
				Gain:      "Unrestricted administrative API access for the lifetime of the stolen token.",
			},
			{
				Number:    3,
				Actor:     "Attacker with admin access",
				Action:    "Create a backdoor service principal with long-lived credentials for persistent access.",
				Technical: "POST /applications with a new App Registration; POST /servicePrincipals; add a client secret with endDateTime set years in the future; assign Global Administrator or Application Administrator role.",
				Technique: "T1136.003",
				EnabledBy: "zt_id_014",
				Gain:      "An independent, attacker-controlled credential that does not depend on the stolen user token.",
			},
			{
				Number:    4,
				Actor:     "Attacker with admin access",
				Action:    "Optionally add an external SAML/OIDC federation trust to the tenant for invisible backdoor access.",
				Technical: "Add a federated identity credential to an existing App Registration pointing to an attacker-controlled IdP, or add a SAML federation domain to the tenant. This allows the attacker to generate valid tokens from their own infrastructure without touching the target tenant's auth flow.",
				Technique: "T1484.002",
				EnabledBy: "zt_id_019",
				Gain:      "Token-issuance capability from attacker infrastructure, completely independent of the target tenant's authentication controls.",
			},
			{
				Number:    5,
				Actor:     "Time (passive evidence destruction)",
				Action:    "Activity Log entries for the persistence operations age out because they are not exported to long-term storage.",
				Technical: "The Activity Log is not exported to Log Analytics or Storage (zt_vis_017). Azure retains Activity Log data for 90 days in the built-in viewer. After 90 days, the evidence of app registration creation, role assignment, and federation trust establishment is permanently purged.",
				Technique: "T1070.003",
				EnabledBy: "zt_vis_017",
				Gain:      "The forensic trail of exactly how persistence was established is destroyed by Azure's own 90-day retention, leaving investigators unable to determine the backdoor mechanism.",
			},
			{
				Number:    6,
				Actor:     "Attacker (months later)",
				Action:    "Return via the backdoor credential to access the tenant long after the original token has expired and the incident is forgotten.",
				Technical: "Authenticate using the backdoor service principal secret or the federated IdP; the original stolen token is long expired, but the persistence mechanisms are unaffected. Investigation finds no Activity Log evidence of how the backdoor was created.",
				Technique: "T1078.004",
				EnabledBy: "zt_vis_017",
				Gain:      "Indefinite, evidence-free access to the tenant via persistence mechanisms whose creation is no longer auditable.",
			},
		},
		BlastRadius: models.BlastRadiusDetail{
			InitialAccess:      "Stolen admin token via AiTM phishing, facilitated by long token lifetime and missing auth strength policy.",
			LateralMovement:    "Direct to Global Admin scope via the stolen token - no lateral movement required.",
			MaxPrivilege:       "Global Administrator with persistent backdoor credentials and optional federation trust.",
			DataAtRisk:         []string{"All Entra ID directory data", "All Azure subscription resources", "All Microsoft 365 data (mail, files, Teams)", "Audit evidence itself (Activity Log not exported)"},
			ServicesAtRisk:     []string{"Entra ID", "Azure Resource Manager", "Microsoft 365", "All services in linked subscriptions"},
			EstimatedScopePerc: "100% of the tenant and all linked subscriptions",
		},
		RegulatoryImpact: []models.RegulatoryViolation{
			{Framework: "PCI DSS 4.0", Control: "8.2.8 / 10.7.1", Impact: "Session management does not limit token lifetime appropriately; audit log retention does not meet the 12-month requirement."},
			{Framework: "ISO 27001:2022", Control: "A.8.5 / A.8.15", Impact: "Secure authentication fails to prevent token replay; logging and monitoring do not provide long-term audit trail."},
			{Framework: "NIST 800-53", Control: "IA-11 / AU-11", Impact: "Re-authentication for privileged operations is not enforced; audit record retention is insufficient for forensic investigation."},
		},
		MinimalFixSet: []string{"zt_id_019", "zt_vis_017"},
		PriorityFix: "Configure a token lifetime policy that reduces access token lifetime to 1 hour or less and enable Continuous Access Evaluation (CAE) to revoke tokens in near-real-time. " +
			"Then export the Activity Log to a Log Analytics Workspace with at least 365-day retention so persistence operations are permanently recorded.",
		BreakingNote: "Reducing token lifetime increases re-authentication frequency for all users, which may impact user experience for long-running sessions. " +
			"CAE requires supported client applications. Activity Log export to Log Analytics incurs ingestion costs proportional to subscription activity volume.",
		MITRETechnique:    "T1550.001 / T1136.003 / T1484.002",
		MITRETactic:       "Credential Access / Persistence / Defense Evasion",
		KillChainPhase:    "Installation",
		AffectedResources: resources,
	}
}