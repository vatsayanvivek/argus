package engine

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// policiesFS embeds the Rego policy tree.
//
// NOTE: //go:embed does not permit parent (`..`) path elements, so policies
// are embedded from a directory local to this package. A build/copy step
// (see Makefile) mirrors argus/policies/ into internal/engine/policies/
// before `go build`. If the directory is empty (only the .keep sentinel),
// NewOPAEngine gracefully returns an engine with zero prepared queries.
//
//go:embed all:policies
var policiesFS embed.FS

// PolicyMetadata is the metadata block that every Rego policy rule exposes
// via a `metadata := { ... }` assignment. ARGUS extracts this block and uses
// it to enrich every finding produced by the policy.
type PolicyMetadata struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	Pillar         string   `json:"pillar"`
	ZTTenet        string   `json:"zt_tenet"`
	NIST80053      string   `json:"nist_800_53"`
	NIST800207     string   `json:"nist_800_207"`
	CISRule        string   `json:"cis_rule"`
	MITRETechnique string   `json:"mitre_technique"`
	MITRETactic    string   `json:"mitre_tactic"`
	ChainRole      string   `json:"chain_role"`
	Frameworks     []string `json:"frameworks"`
	Source         string   `json:"source"`
}

// OPAEngine is the embedded OPA evaluator. Each policy is parsed once at
// startup and kept around as a prepared query for fast repeated evaluation.
//
// compliancePacks holds the parsed compliance framework mappings
// loaded from policies/compliance/*.json at engine init. Keyed by
// canonical framework name (e.g. "soc2", "hipaa", "pci-dss-4",
// "iso-27001"). Empty map when no packs are present, which is the safe
// default.
type OPAEngine struct {
	queries         map[string]rego.PreparedEvalQuery
	metadata        map[string]PolicyMetadata
	compliancePacks map[string]*CompliancePack
}

// NewOPAEngine walks the embedded policy tree, parses every .rego file,
// extracts the `metadata` rule, and prepares a query for `data.<pkg>.violation`.
// It tolerates a completely empty policy tree and returns a usable (but
// zero-rule) engine if no .rego files are found.
func NewOPAEngine() (*OPAEngine, error) {
	e := &OPAEngine{
		queries:         make(map[string]rego.PreparedEvalQuery),
		metadata:        make(map[string]PolicyMetadata),
		compliancePacks: make(map[string]*CompliancePack),
	}

	ctx := context.Background()

	err := fs.WalkDir(policiesFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Missing root (no embed matches) is tolerated.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".rego") {
			return nil
		}

		content, readErr := policiesFS.ReadFile(path)
		if readErr != nil {
			return nil // best-effort: skip unreadable file
		}

		module, parseErr := ast.ParseModule(path, string(content))
		if parseErr != nil || module == nil {
			return nil // skip unparseable policy rather than failing boot
		}

		meta, ok := extractMetadata(module)
		if !ok || meta.ID == "" {
			return nil
		}

		pkgPath := module.Package.Path.String() // e.g. data.argus.cis.storage_1_1
		query := fmt.Sprintf("%s.violation", pkgPath)

		prepared, prepErr := rego.New(
			rego.Query(query),
			rego.ParsedModule(module),
		).PrepareForEval(ctx)
		if prepErr != nil {
			return nil // skip this module, keep loading others
		}

		e.queries[meta.ID] = prepared
		e.metadata[meta.ID] = meta
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk policies: %w", err)
	}

	// Load compliance framework packs from policies/compliance/*.json.
	// Failure to load packs is non-fatal — ARGUS must still evaluate
	// Rego policies even if mapping files are absent or unparseable.
	if packs, perr := loadCompliancePacks(); perr == nil && packs != nil {
		e.compliancePacks = packs
	}

	return e, nil
}

// extractMetadata finds the `metadata := { ... }` rule in a parsed Rego
// module and decodes it into a PolicyMetadata struct.
func extractMetadata(module *ast.Module) (PolicyMetadata, bool) {
	var meta PolicyMetadata
	for _, rule := range module.Rules {
		if rule.Head == nil || string(rule.Head.Name) != "metadata" {
			continue
		}
		// Value should be an ast.Object literal.
		val := rule.Head.Value
		if val == nil {
			continue
		}
		// Serialize the term via JSON, which works for any Rego value that
		// is JSON-compatible (objects, arrays, strings, numbers, booleans).
		raw, err := termToInterface(val)
		if err != nil {
			continue
		}
		obj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		meta.ID = stringOr(obj, "id", "")
		meta.Title = stringOr(obj, "title", "")
		meta.Description = stringOr(obj, "description", "")
		meta.Severity = stringOr(obj, "severity", "MEDIUM")
		meta.Pillar = stringOr(obj, "pillar", "")
		meta.ZTTenet = stringOr(obj, "zt_tenet", "")
		meta.NIST80053 = stringOr(obj, "nist_800_53", "")
		meta.NIST800207 = stringOr(obj, "nist_800_207", "")
		meta.CISRule = stringOr(obj, "cis_rule", "")
		meta.MITRETechnique = stringOr(obj, "mitre_technique", "")
		meta.MITRETactic = stringOr(obj, "mitre_tactic", "")
		meta.ChainRole = stringOr(obj, "chain_role", "")
		meta.Source = stringOr(obj, "source", "")
		meta.Frameworks = stringSliceOr(obj, "frameworks")
		return meta, true
	}
	return meta, false
}

// termToInterface converts an ast.Term (and therefore its ast.Value) into a
// native Go value: map[string]interface{}, []interface{}, string, float64,
// bool, or nil. It walks the Rego AST directly so that we do not depend on
// any unexported helpers.
func termToInterface(term *ast.Term) (interface{}, error) {
	if term == nil {
		return nil, fmt.Errorf("nil term")
	}
	return valueToInterface(term.Value)
}

func valueToInterface(v ast.Value) (interface{}, error) {
	switch t := v.(type) {
	case ast.Null:
		return nil, nil
	case ast.Boolean:
		return bool(t), nil
	case ast.Number:
		// ast.Number is a json.Number-compatible string; parse as float.
		if f, err := json.Number(string(t)).Float64(); err == nil {
			return f, nil
		}
		return string(t), nil
	case ast.String:
		return string(t), nil
	case ast.Var:
		return string(t), nil
	case *ast.Array:
		out := make([]interface{}, 0, t.Len())
		var walkErr error
		t.Foreach(func(elem *ast.Term) {
			if walkErr != nil {
				return
			}
			iv, err := termToInterface(elem)
			if err != nil {
				walkErr = err
				return
			}
			out = append(out, iv)
		})
		return out, walkErr
	case ast.Object:
		out := make(map[string]interface{}, t.Len())
		var walkErr error
		t.Foreach(func(k, val *ast.Term) {
			if walkErr != nil {
				return
			}
			ks, ok := k.Value.(ast.String)
			if !ok {
				// Non-string keys are not representable in plain JSON;
				// stringify via the term's own Rego form.
				walkErr = fmt.Errorf("non-string object key: %s", k.String())
				return
			}
			iv, err := termToInterface(val)
			if err != nil {
				walkErr = err
				return
			}
			out[string(ks)] = iv
		})
		return out, walkErr
	case ast.Set:
		out := make([]interface{}, 0, t.Len())
		var walkErr error
		t.Foreach(func(elem *ast.Term) {
			if walkErr != nil {
				return
			}
			iv, err := termToInterface(elem)
			if err != nil {
				walkErr = err
				return
			}
			out = append(out, iv)
		})
		return out, walkErr
	}
	// Fallback: rely on the value's String() representation.
	return v.String(), nil
}

func stringOr(m map[string]interface{}, key, def string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	return s
}

func stringSliceOr(m map[string]interface{}, key string) []string {
	out := []string{}
	v, ok := m[key]
	if !ok || v == nil {
		return out
	}
	arr, ok := v.([]interface{})
	if !ok {
		return out
	}
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// RuleCount returns the total number of Rego policies the engine
// successfully loaded and prepared for evaluation.
func (e *OPAEngine) RuleCount() int {
	if e == nil {
		return 0
	}
	return len(e.queries)
}

// RuleCountBySource returns per-source policy counts (cis, zt, iac,
// etc.) based on the "source" field in each policy's metadata block.
// Policies whose metadata lacks a source, or set it to empty, fall
// under the "unknown" bucket.
func (e *OPAEngine) RuleCountBySource() map[string]int {
	out := map[string]int{}
	if e == nil {
		return out
	}
	for _, m := range e.metadata {
		src := m.Source
		if src == "" {
			src = "unknown"
		}
		out[src]++
	}
	return out
}

// severityRank is defined in correlator.go (same package).

// Evaluate runs every prepared policy against the given snapshot and
// returns a sorted slice of findings. The complianceFilter argument
// accepts four flavours:
//
//  1. "" or "all"        — every loaded rule is evaluated.
//  2. A legacy framework name ("cis-azure-2.0", "nist-800-207",
//     "nist-800-53") — the rule's metadata.frameworks slice is
//     consulted and rules not tagged with the filter are skipped.
//     This preserves backwards-compatibility with v1.5.
//  3. A compliance-pack framework name ("soc2", "hipaa", "pci-dss-4",
//     "iso-27001") — only rules that appear in the pack's mapping
//     table are evaluated, and findings are decorated with the
//     corresponding control IDs.
//  4. An unknown filter string — treated like case (2); zero matches
//     will silently return no findings, which is the historical
//     behaviour.
//
// Findings carry compliance-control decorations whenever a loaded pack
// maps their rule ID, regardless of which filter value was used —
// callers running "all" still see SOC 2 / HIPAA / PCI / ISO control
// citations for every rule that has mappings. The filter's only job
// is to decide which rules *run*; enrichment is independent of it.
func (e *OPAEngine) Evaluate(snapshot *models.AzureSnapshot, complianceFilter string) ([]models.Finding, error) {
	ctx := context.Background()
	input := TransformSnapshot(snapshot)

	findings := make([]models.Finding, 0, 64)

	// If the filter names a loaded compliance pack, restrict evaluation
	// to rules that pack references. This is the v1.6 behaviour.
	// packFilter is nil when the filter is "all" / empty / a legacy
	// framework name.
	var packFilter *CompliancePack
	if complianceFilter != "" && complianceFilter != "all" {
		packFilter = e.CompliancePack(complianceFilter)
	}

	for id, query := range e.queries {
		meta := e.metadata[id]

		switch {
		case packFilter != nil:
			// Compliance-pack filter: rule must appear in the pack's
			// mapping table. Rules with no mapping are excluded
			// because they produce no citation and would confuse a
			// framework-specific report.
			if _, mapped := packFilter.Mappings[id]; !mapped {
				continue
			}
		case complianceFilter != "" && complianceFilter != "all":
			// Legacy framework filter (cis-azure-2.0, nist-800-207,
			// nist-800-53): use the rule's own Frameworks slice.
			if !containsFold(meta.Frameworks, complianceFilter) {
				continue
			}
		}

		results, err := query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			// Skip evaluation errors for a single policy so one bad rule
			// does not break the whole scan.
			continue
		}

		for _, result := range results {
			for _, expr := range result.Expressions {
				violations := expressionAsViolationList(expr.Value)
				for _, v := range violations {
					f := buildFinding(meta, snapshot, v)
					// Decorate with compliance control IDs from every
					// loaded pack so downstream renderers can cite them
					// without another engine lookup.
					if ctrls := e.ControlsForRule(id); len(ctrls) > 0 {
						if f.ComplianceMappings == nil {
							f.ComplianceMappings = map[string][]string{}
						}
						for fw, ids := range ctrls {
							f.ComplianceMappings[fw] = ids
						}
					}
					findings = append(findings, f)
				}
			}
		}
	}

	findings = CollapseDuplicates(findings)

	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		return findings[i].ID < findings[j].ID
	})

	return findings, nil
}

// CollapseDuplicates reduces the noise from rules that fire many times
// for a single logical configuration gap. When the same (rule_id,
// subscription-scope-ish) pair produces multiple findings whose only
// difference is the specific resource they named, we keep one finding
// and list the rest of the resources in AffectedResources.
//
// This matters most for rules like zt_vis_001 ("Security-relevant
// resource has no diagnostic settings") that legitimately fire on every
// KV / SQL / Storage / AKS in the subscription when the fix is often
// a single Activity Log Profile. Before this, a 20-resource sub would
// emit 20 identical findings; after, it emits one finding that names
// all 20 resources.
//
// The deduplication is conservative: two findings are considered the
// "same logical issue" only if they share rule ID, severity, title,
// and scope. Distinct-but-same-rule gaps (e.g. two storage accounts
// each with its own unique misconfig) remain separate because their
// detail strings diverge and the collapse key includes the detail
// string for resource-scope findings.
func CollapseDuplicates(findings []models.Finding) []models.Finding {
	if len(findings) == 0 {
		return findings
	}
	type key struct {
		id, title, scope, detail string
	}
	index := make(map[key]int, len(findings))
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		// Only collapse when the rule fires many times for what is
		// meaningfully one issue. Resource-scope findings with distinct
		// detail strings are kept separate (they describe distinct
		// misconfigurations on distinct resources). Subscription-scope
		// and tenant-scope findings collapse on (id, title, scope) so
		// the single logical issue surfaces once.
		k := key{id: f.ID, title: f.Title, scope: f.Scope}
		if f.Scope == models.ScopeResource {
			// Two resource-scope findings collapse only if they are
			// truly identical (same detail). Different details =
			// different misconfig, keep them separate.
			k.detail = f.Detail
		}
		if i, ok := index[k]; ok {
			// Merge extra resources into the canonical entry.
			if f.ResourceID != "" && f.ResourceID != out[i].ResourceID {
				out[i].AffectedResources = append(out[i].AffectedResources, f.ResourceID)
			}
			continue
		}
		index[k] = len(out)
		out = append(out, f)
	}
	return out
}

// PolicyMetadata returns a copy of the metadata map so callers can introspect
// the full catalog of loaded policies.
func (e *OPAEngine) PolicyMetadata() map[string]PolicyMetadata {
	out := make(map[string]PolicyMetadata, len(e.metadata))
	for k, v := range e.metadata {
		out[k] = v
	}
	return out
}

// expressionAsViolationList coerces whatever the rego `violation` rule
// returned into a slice of map-shaped violations. Policies are expected to
// return a set/array of objects, but a single object is also accepted.
func expressionAsViolationList(val interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	switch v := val.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
	case map[string]interface{}:
		out = append(out, v)
	}
	return out
}

func buildFinding(meta PolicyMetadata, snapshot *models.AzureSnapshot, v map[string]interface{}) models.Finding {
	severity := stringOr(v, "severity", meta.Severity)
	if severity == "" {
		severity = "MEDIUM"
	}
	chainRole := stringOr(v, "chain_role", meta.ChainRole)

	resourceID := stringOr(v, "resource_id", "")
	resourceType := stringOr(v, "resource_type", "")
	resourceName := stringOr(v, "resource_name", "")
	resourceGroup := ""
	location := ""

	// Augment resource metadata by cross-referencing the snapshot.
	if resourceID != "" {
		for _, r := range snapshot.Resources {
			if strings.EqualFold(r.ID, resourceID) {
				if resourceType == "" {
					resourceType = r.Type
				}
				if resourceName == "" {
					resourceName = r.Name
				}
				resourceGroup = r.ResourceGroup
				location = r.Location
				break
			}
		}
	}

	evidence := map[string]interface{}{}
	if e, ok := v["evidence"].(map[string]interface{}); ok {
		evidence = e
	}

	frameworks := append([]string(nil), meta.Frameworks...)
	if len(frameworks) == 0 {
		frameworks = []string{}
	}

	return models.Finding{
		ID:                   stringOr(v, "rule_id", meta.ID),
		Source:               meta.Source,
		ResourceID:           resourceID,
		ResourceType:         resourceType,
		ResourceName:         resourceName,
		ResourceGroup:        resourceGroup,
		Location:             location,
		Scope:                classifyScope(resourceID, resourceType),
		Severity:             strings.ToUpper(severity),
		Pillar:               meta.Pillar,
		CISRule:              meta.CISRule,
		CISLevel:             stringOr(v, "cis_level", ""),
		NIST80053Control:     meta.NIST80053,
		NIST800207Tenet:      meta.NIST800207,
		MITRETechnique:       meta.MITRETechnique,
		MITRETactic:          meta.MITRETactic,
		Frameworks:           frameworks,
		Title:                stringOr(v, "title", meta.Title),
		Description:          meta.Description,
		Detail:               stringOr(v, "detail", ""),
		Evidence:             evidence,
		ChainRole:            chainRole,
		ParticipatesInChains: []string{},
	}
}

// classifyScope inspects a finding's resource identifier and returns one
// of tenant / subscription / resource-group / resource. The scope lets
// consumers (the IaC command, the HTML findings table, the compliance
// evidence packer) collapse, filter, or group findings by the level at
// which they need to be remediated, rather than treating every finding
// as "some resource".
//
// Heuristics, in order:
//   1. Empty ID or a literal "tenant" / "directory" string → tenant
//   2. Full ARM resource path (/subscriptions/<g>/resourceGroups/<n>/providers/…) → resource
//   3. RG-only path (/subscriptions/<g>/resourceGroups/<n>) → resource-group
//   4. Subscription-only path (/subscriptions/<g>) → subscription
//   5. Anything else that looks like a Defender plan name or a
//      subscription-level placeholder → subscription
//   6. Fallback → resource (safest default for an unrecognised ID that
//      at least looked like something)
func classifyScope(resourceID, resourceType string) string {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return models.ScopeTenant
	}
	low := strings.ToLower(id)
	if low == "tenant" || low == "directory" || low == "/" {
		return models.ScopeTenant
	}
	// ARM resource path
	if strings.Contains(low, "/providers/") && strings.Contains(low, "/subscriptions/") {
		return models.ScopeResource
	}
	if strings.Contains(low, "/resourcegroups/") && strings.HasPrefix(low, "/subscriptions/") {
		return models.ScopeResourceGroup
	}
	if strings.HasPrefix(low, "/subscriptions/") {
		return models.ScopeSubscription
	}
	// Subscription-level placeholders used by some rules where the
	// "resource" is really a subscription-scoped configuration: Defender
	// plan names, the literal string "subscription", terraform-plan
	// sentinel in IaC mode, etc.
	if resourceType == "" {
		switch low {
		case "subscription", "subscriptions", "terraform-plan":
			return models.ScopeSubscription
		}
	}
	// Defender plan names land here: "VirtualMachines", "Containers",
	// "KeyVaults", "SqlServers", etc. They don't look like ARM paths but
	// they fire once per subscription per plan.
	if looksLikeDefenderPlanName(id) {
		return models.ScopeSubscription
	}
	return models.ScopeResource
}

// looksLikeDefenderPlanName reports whether an identifier is likely one
// of the Azure Defender for Cloud pricing plan names, which fire as a
// subscription-scope finding rather than a per-resource one.
func looksLikeDefenderPlanName(s string) bool {
	switch s {
	case "VirtualMachines", "AppServices", "SqlServers", "SqlServerVirtualMachines",
		"OpenSourceRelationalDatabases", "StorageAccounts", "Containers",
		"KeyVaults", "Dns", "Arm", "CosmosDbs", "CloudPosture", "Api", "Apis":
		return true
	}
	return false
}

func containsFold(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}

// TransformSnapshot produces the JSON-shaped input passed to the OPA
// evaluator. The top-level keys mirror what Rego policies expect (for
// example `input.storage_accounts`) so policies can stay declarative.
func TransformSnapshot(snapshot *models.AzureSnapshot) map[string]interface{} {
	if snapshot == nil {
		return map[string]interface{}{}
	}

	input := map[string]interface{}{
		"subscription": map[string]interface{}{
			"id":        snapshot.SubscriptionID,
			"name":      snapshot.SubscriptionName,
			"tenant_id": snapshot.TenantID,
		},
		"resources":                   resourcesAsJSON(snapshot.Resources),
		"virtual_machines":            filterByType(snapshot.Resources, "microsoft.compute/virtualmachines"),
		"storage_accounts":            filterByType(snapshot.Resources, "microsoft.storage/storageaccounts"),
		"sql_servers":                 filterByType(snapshot.Resources, "microsoft.sql/servers"),
		"key_vaults":                  filterByType(snapshot.Resources, "microsoft.keyvault/vaults"),
		"network_security_groups":     filterByType(snapshot.Resources, "microsoft.network/networksecuritygroups"),
		"virtual_networks":            filterByType(snapshot.Resources, "microsoft.network/virtualnetworks"),
		"app_services":                filterAppServices(snapshot.Resources),
		"aks_clusters":                filterByType(snapshot.Resources, "microsoft.containerservice/managedclusters"),
		"function_apps":               filterFunctionApps(snapshot.Resources),
		"app_gateways":                filterByType(snapshot.Resources, "microsoft.network/applicationgateways"),
		"public_ips":                  filterByType(snapshot.Resources, "microsoft.network/publicipaddresses"),
		"subnets":                     subnetsAsJSON(snapshot.NetworkTopology.Subnets),
		"vnets":                       vnetsAsJSON(snapshot.NetworkTopology.VNets),
		"nsgs":                        nsgsAsJSON(snapshot.NetworkTopology.NSGs),
		"users":                       usersAsJSON(snapshot.Identity.Users),
		"service_principals":          servicePrincipalsAsJSON(snapshot.Identity.ServicePrincipals),
		"app_registrations":           appRegistrationsAsJSON(snapshot.Identity.AppRegistrations),
		"managed_identities":          managedIdentitiesAsJSON(snapshot.Identity.ManagedIdentities),
		"conditional_access_policies": capsAsJSON(snapshot.Identity.ConditionalAccess),
		"pim_assignments":             pimAsJSON(snapshot.Identity.PIMAssignments),
		"role_assignments":            roleAssignmentsAsJSON(snapshot.Identity.RoleAssignments),
		"access_reviews":              accessReviewsAsJSON(snapshot.Identity.AccessReviews),
		"tenant_settings":             tenantSettingsAsJSON(snapshot.Identity.TenantSettings),
		"defender_plans":              defenderPlansAsJSON(snapshot.DefenderPlans),
		"defender_findings":           defenderFindingsAsJSON(snapshot.DefenderFindings),
		"diagnostic_settings":         diagnosticSettingsAsJSON(snapshot.DiagnosticSettings),
		"activity_log":                activityLogAsJSON(snapshot.ActivityLog),
		"policy_compliance":           policyComplianceAsJSON(snapshot.PolicyCompliance),
		"secure_score":                snapshot.SecureScore,
	}
	return input
}

// filterByType returns every resource whose type matches the given
// (case-insensitive) Azure resource type, as a Rego-compatible []interface{}.
func filterByType(resources []models.AzureResource, rtype string) []interface{} {
	out := []interface{}{}
	target := strings.ToLower(rtype)
	for _, r := range resources {
		if strings.ToLower(r.Type) != target {
			continue
		}
		out = append(out, resourceToJSON(r))
	}
	return out
}

// filterAppServices returns Microsoft.Web/sites entries that are NOT
// function apps (those are returned separately).
func filterAppServices(resources []models.AzureResource) []interface{} {
	out := []interface{}{}
	for _, r := range resources {
		if strings.ToLower(r.Type) != "microsoft.web/sites" {
			continue
		}
		if strings.Contains(strings.ToLower(r.Kind), "functionapp") {
			continue
		}
		out = append(out, resourceToJSON(r))
	}
	return out
}

// filterFunctionApps returns function-app entries from the Web/sites type.
func filterFunctionApps(resources []models.AzureResource) []interface{} {
	out := []interface{}{}
	for _, r := range resources {
		if strings.ToLower(r.Type) != "microsoft.web/sites" {
			continue
		}
		if !strings.Contains(strings.ToLower(r.Kind), "functionapp") {
			continue
		}
		out = append(out, resourceToJSON(r))
	}
	return out
}

func resourceToJSON(r models.AzureResource) map[string]interface{} {
	return map[string]interface{}{
		"id":             r.ID,
		"name":           r.Name,
		"type":           r.Type,
		"location":       r.Location,
		"resource_group": r.ResourceGroup,
		"properties":     r.Properties,
		"tags":           stringMapAsJSON(r.Tags),
		"sku":            r.SKU,
		"kind":           r.Kind,
	}
}

func resourcesAsJSON(resources []models.AzureResource) []interface{} {
	out := make([]interface{}, 0, len(resources))
	for _, r := range resources {
		out = append(out, resourceToJSON(r))
	}
	return out
}

func stringMapAsJSON(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func subnetsAsJSON(subnets []models.Subnet) []interface{} {
	out := make([]interface{}, 0, len(subnets))
	for _, s := range subnets {
		out = append(out, map[string]interface{}{
			"id":      s.ID,
			"name":    s.Name,
			"vnet_id": s.VNetID,
			"cidr":    s.CIDR,
			"nsg_id":  s.NSGID,
			"has_nsg": s.HasNSG,
		})
	}
	return out
}

func vnetsAsJSON(vnets []models.VirtualNetwork) []interface{} {
	out := make([]interface{}, 0, len(vnets))
	for _, v := range vnets {
		addrs := make([]interface{}, 0, len(v.AddressSpace))
		for _, a := range v.AddressSpace {
			addrs = append(addrs, a)
		}
		out = append(out, map[string]interface{}{
			"id":             v.ID,
			"name":           v.Name,
			"address_space":  addrs,
			"resource_group": v.ResourceGroup,
			"ddos_enabled":   v.DDoSEnabled,
		})
	}
	return out
}

func nsgsAsJSON(nsgs []models.NetworkSecurityGroup) []interface{} {
	out := make([]interface{}, 0, len(nsgs))
	for _, n := range nsgs {
		out = append(out, map[string]interface{}{
			"id":                n.ID,
			"name":              n.Name,
			"resource_group":    n.ResourceGroup,
			"inbound_rules":     nsgRulesAsJSON(n.InboundRules),
			"outbound_rules":    nsgRulesAsJSON(n.OutboundRules),
			"flow_logs_enabled": n.FlowLogsEnabled,
		})
	}
	return out
}

func nsgRulesAsJSON(rules []models.NSGRule) []interface{} {
	out := make([]interface{}, 0, len(rules))
	for _, r := range rules {
		out = append(out, map[string]interface{}{
			"name":                       r.Name,
			"protocol":                   r.Protocol,
			"direction":                  r.Direction,
			"access":                     r.Access,
			"priority":                   r.Priority,
			"source_address_prefix":      r.SourceAddressPrefix,
			"source_port_range":          r.SourcePortRange,
			"destination_address_prefix": r.DestinationAddressPrefix,
			"destination_port_range":     r.DestinationPortRange,
		})
	}
	return out
}

func usersAsJSON(users []models.AADUser) []interface{} {
	out := make([]interface{}, 0, len(users))
	for _, u := range users {
		roles := make([]interface{}, 0, len(u.AssignedRoles))
		for _, r := range u.AssignedRoles {
			roles = append(roles, r)
		}
		out = append(out, map[string]interface{}{
			"id":                       u.ID,
			"display_name":             u.DisplayName,
			"user_principal_name":      u.UserPrincipalName,
			"account_enabled":          u.AccountEnabled,
			"user_type":                u.UserType,
			"assigned_roles":           roles,
			"on_premises_sync_enabled": u.OnPremisesSyncEnabled,
			"last_signin_datetime":     u.LastSignInDateTime,
			"mfa_enabled":              u.MFAEnabled,
		})
	}
	return out
}

func servicePrincipalsAsJSON(sps []models.ServicePrincipal) []interface{} {
	out := make([]interface{}, 0, len(sps))
	for _, sp := range sps {
		appRoles := make([]interface{}, 0, len(sp.AppRoles))
		for _, r := range sp.AppRoles {
			appRoles = append(appRoles, r)
		}
		out = append(out, map[string]interface{}{
			"id":                     sp.ID,
			"display_name":           sp.DisplayName,
			"app_id":                 sp.AppID,
			"service_principal_type": sp.ServicePrincipalType,
			"password_credentials":   credentialsAsJSON(sp.PasswordCredentials),
			"key_credentials":        credentialsAsJSON(sp.KeyCredentials),
			"app_roles":              appRoles,
			"account_enabled":        sp.AccountEnabled,
		})
	}
	return out
}

func credentialsAsJSON(creds []models.Credential) []interface{} {
	out := make([]interface{}, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]interface{}{
			"key_id":          c.KeyID,
			"start_datetime":  c.StartDateTime,
			"end_datetime":    c.EndDateTime,
			"display_name":    c.DisplayName,
		})
	}
	return out
}

func appRegistrationsAsJSON(apps []models.AppRegistration) []interface{} {
	out := make([]interface{}, 0, len(apps))
	for _, a := range apps {
		ra := make([]interface{}, 0, len(a.RequiredResourceAccess))
		for _, r := range a.RequiredResourceAccess {
			perms := make([]interface{}, 0, len(r.Permissions))
			for _, p := range r.Permissions {
				perms = append(perms, map[string]interface{}{
					"id":   p.ID,
					"type": p.Type,
				})
			}
			ra = append(ra, map[string]interface{}{
				"resource_app_id": r.ResourceAppID,
				"permissions":     perms,
			})
		}
		out = append(out, map[string]interface{}{
			"id":                       a.ID,
			"display_name":             a.DisplayName,
			"app_id":                   a.AppID,
			"password_credentials":     credentialsAsJSON(a.PasswordCredentials),
			"required_resource_access": ra,
		})
	}
	return out
}

func managedIdentitiesAsJSON(mis []models.ManagedIdentity) []interface{} {
	out := make([]interface{}, 0, len(mis))
	for _, m := range mis {
		rids := make([]interface{}, 0, len(m.ResourceIDs))
		for _, r := range m.ResourceIDs {
			rids = append(rids, r)
		}
		out = append(out, map[string]interface{}{
			"id":            m.ID,
			"name":          m.Name,
			"type":          m.Type,
			"principal_id":  m.PrincipalID,
			"resource_ids":  rids,
		})
	}
	return out
}

func capsAsJSON(caps []models.ConditionalAccessPolicy) []interface{} {
	out := make([]interface{}, 0, len(caps))
	for _, c := range caps {
		out = append(out, map[string]interface{}{
			"id":             c.ID,
			"display_name":   c.DisplayName,
			"state":          c.State,
			"conditions":     c.Conditions,
			"grant_controls": c.GrantControls,
		})
	}
	return out
}

func pimAsJSON(pim []models.PIMAssignment) []interface{} {
	out := make([]interface{}, 0, len(pim))
	for _, p := range pim {
		out = append(out, map[string]interface{}{
			"id":                 p.ID,
			"role_definition_id": p.RoleDefinitionID,
			"role_name":          p.RoleName,
			"principal_id":       p.PrincipalID,
			"principal_name":     p.PrincipalName,
			"assignment_type":    p.AssignmentType,
			"start_datetime":     p.StartDateTime,
			"end_datetime":       p.EndDateTime,
		})
	}
	return out
}

func roleAssignmentsAsJSON(ras []models.RoleAssignment) []interface{} {
	out := make([]interface{}, 0, len(ras))
	for _, r := range ras {
		out = append(out, map[string]interface{}{
			"id":                 r.ID,
			"role_definition_id": r.RoleDefinitionID,
			"role_name":          r.RoleName,
			"principal_id":       r.PrincipalID,
			"principal_type":     r.PrincipalType,
			"scope":              r.Scope,
		})
	}
	return out
}

func accessReviewsAsJSON(ars []models.AccessReview) []interface{} {
	out := make([]interface{}, 0, len(ars))
	for _, a := range ars {
		revs := make([]interface{}, 0, len(a.Reviewers))
		for _, r := range a.Reviewers {
			revs = append(revs, r)
		}
		out = append(out, map[string]interface{}{
			"id":           a.ID,
			"display_name": a.DisplayName,
			"status":       a.Status,
			"reviewers":    revs,
			"scope":        a.Scope,
		})
	}
	return out
}

func tenantSettingsAsJSON(t models.TenantSettings) map[string]interface{} {
	return map[string]interface{}{
		"legacy_auth_enabled":             t.LegacyAuthEnabled,
		"guest_user_permissions":          t.GuestUserPermissions,
		"guest_invite_restrictions":       t.GuestInviteRestrictions,
		"cross_tenant_access_unrestricted": t.CrossTenantAccessUnrestricted,
		"password_reset_notification":     t.PasswordResetNotification,
	}
}

func defenderPlansAsJSON(plans map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(plans))
	for k, v := range plans {
		out[k] = v
	}
	return out
}

func defenderFindingsAsJSON(findings []models.DefenderFinding) []interface{} {
	out := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]interface{}{
			"id":              f.ID,
			"name":            f.Name,
			"display_name":    f.DisplayName,
			"severity":        f.Severity,
			"status":          f.Status,
			"resource_id":     f.ResourceID,
			"description":     f.Description,
			"remediation_url": f.RemediationURL,
		})
	}
	return out
}

func diagnosticSettingsAsJSON(ds map[string]bool) map[string]interface{} {
	out := make(map[string]interface{}, len(ds))
	for k, v := range ds {
		out[k] = v
	}
	return out
}

func activityLogAsJSON(events []models.ActivityEvent) []interface{} {
	out := make([]interface{}, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]interface{}{
			"operation_name": e.OperationName,
			"caller":         e.Caller,
			"resource_id":    e.ResourceID,
			"resource_type":  e.ResourceType,
			"status":         e.Status,
			"timestamp":      e.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			"category":       e.Category,
		})
	}
	return out
}

func policyComplianceAsJSON(results []models.PolicyResult) []interface{} {
	out := make([]interface{}, 0, len(results))
	for _, r := range results {
		ncr := make([]interface{}, 0, len(r.NonCompliantResources))
		for _, id := range r.NonCompliantResources {
			ncr = append(ncr, id)
		}
		out = append(out, map[string]interface{}{
			"policy_name":             r.PolicyName,
			"policy_assignment_id":    r.PolicyAssignmentID,
			"compliance_state":        r.ComplianceState,
			"non_compliant_count":     r.NonCompliantCount,
			"non_compliant_resources": ncr,
		})
	}
	return out
}
