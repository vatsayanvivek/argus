package iac

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// ARMTemplate is the narrow view of an ARM deployment template that
// ARGUS needs. Bicep-compiled JSON uses the identical envelope; this
// single type therefore serves both formats.
//
// As of v1.8 ARGUS evaluates ARM expressions at scan time:
//
//   * Pure functions (parameters, variables, concat, format, if,
//     resourceId, 30+ more) resolve to their concrete values against
//     Parameters + Variables.
//   * Runtime-only functions (reference, listKeys, environment,
//     subscription, resourceGroup, deployment, etc.) evaluate to
//     opaque markers. Rules that match on specific string values
//     won't match these markers — the correct behaviour, since we
//     can't confirm or deny the rule's predicate.
//
// The evaluator is in arm_expr.go. Resolution happens in
// ParseARMTemplate before Translate walks the resources.
type ARMTemplate struct {
	Schema         string                 `json:"$schema"`
	ContentVersion string                 `json:"contentVersion"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
	Variables      map[string]interface{} `json:"variables,omitempty"`
	Resources      []ARMResource          `json:"resources"`
}

// ARMResource is one entry from the ARM template's resources[]. The
// Type is a canonical Microsoft.* ARM type — the same string the Rego
// rules match against in live Azure Resource Graph output — so no
// name remapping is required.
//
// Properties carries the resource-specific configuration block. For a
// storage account that's supportsHttpsTrafficOnly, minimumTlsVersion,
// networkAcls, etc.; for a key vault, enablePurgeProtection,
// enableRbacAuthorization, etc. These match the live Azure shape
// exactly since ARM is the declarative form of Resource Graph.
type ARMResource struct {
	Type       string                 `json:"type"`
	APIVersion string                 `json:"apiVersion"`
	Name       string                 `json:"name"`
	Location   string                 `json:"location"`
	Kind       string                 `json:"kind,omitempty"`
	SKU        interface{}            `json:"sku,omitempty"` // can be string or object
	Tags       map[string]string      `json:"tags,omitempty"`
	Properties map[string]interface{} `json:"properties"`
	// Child resources are nested under their parent in ARM templates
	// (and Bicep). We flatten them during translation so rules that
	// target child types (Microsoft.Sql/servers/databases, etc.) can
	// still fire.
	NestedResources []ARMResource `json:"resources,omitempty"`
}

// ParseARMTemplate decodes ARM deployment template JSON and then
// resolves every ARM expression in the resources array. The same
// function accepts Bicep-compiled JSON (which contains no expressions
// because Bicep resolves them at compile time); resolution is a no-op
// in that case.
//
// Expression resolution populates parameter default values so that
// `[parameters('foo')]` references resolve to their declared
// `defaultValue` when `value` wasn't provided. This matches ARM's own
// behaviour when a deployment is submitted without overriding
// parameters.
func ParseARMTemplate(payload []byte) (*ARMTemplate, error) {
	var tpl ARMTemplate
	if err := json.Unmarshal(payload, &tpl); err != nil {
		return nil, fmt.Errorf("parse ARM template: %w", err)
	}
	if len(tpl.Resources) == 0 {
		return nil, fmt.Errorf("ARM template has no resources[] array")
	}
	// Build evaluation context from the template's parameters and
	// variables blocks. Variables can reference parameters, so resolve
	// them in dependency order — a two-pass is sufficient because ARM
	// templates don't allow deeper nesting (variables → variables →
	// parameters is the typical max).
	ctx := &ARMExprContext{
		Parameters: tpl.Parameters,
		Variables:  map[string]interface{}{},
	}
	// First pass: copy variables, resolving against parameters only.
	for k, v := range tpl.Variables {
		ctx.Variables[k] = ResolveARMValue(v, ctx)
	}
	// Second pass: resolve variables against themselves + parameters.
	for k, v := range tpl.Variables {
		ctx.Variables[k] = ResolveARMValue(v, ctx)
	}
	// Now resolve every resource in place.
	for i := range tpl.Resources {
		tpl.Resources[i] = resolveARMResource(tpl.Resources[i], ctx)
	}
	return &tpl, nil
}

// resolveARMResource walks a resource, evaluating every ARM
// expression in its scalar fields + the Properties map + Tags, then
// recursively descending into nested child resources.
func resolveARMResource(r ARMResource, ctx *ARMExprContext) ARMResource {
	r.Type = resolveStringIfExpr(r.Type, ctx)
	r.APIVersion = resolveStringIfExpr(r.APIVersion, ctx)
	r.Name = resolveStringIfExpr(r.Name, ctx)
	r.Location = resolveStringIfExpr(r.Location, ctx)
	r.Kind = resolveStringIfExpr(r.Kind, ctx)
	if r.SKU != nil {
		r.SKU = ResolveARMValue(r.SKU, ctx)
	}
	if r.Properties != nil {
		if resolved, ok := ResolveARMValue(r.Properties, ctx).(map[string]interface{}); ok {
			r.Properties = resolved
		}
	}
	if r.Tags != nil {
		for k, v := range r.Tags {
			r.Tags[k] = resolveStringIfExpr(v, ctx)
		}
	}
	for i := range r.NestedResources {
		r.NestedResources[i] = resolveARMResource(r.NestedResources[i], ctx)
	}
	return r
}

// resolveStringIfExpr calls the expression resolver on a string,
// coercing the result back to a string representation. Non-string
// return values (numbers, bools) render via toString; objects/arrays
// render as JSON which is defensible behaviour for scalar fields that
// accidentally evaluated to a complex value.
func resolveStringIfExpr(s string, ctx *ARMExprContext) string {
	resolved := resolveARMString(s, ctx)
	return toString(resolved)
}

// TranslateARM produces an AzureSnapshot from a parsed ARM template so
// the OPA engine can evaluate the same 201 policies against the
// planned state. Because ARM already uses canonical Microsoft.* type
// names and property naming conventions, the translator is largely a
// shape adapter — no per-type switch statement is required.
//
// The translator walks nested resources (ARM allows child resources
// to sit under their parent, which Bicep uses heavily for things like
// SQL databases under a SQL server) and emits them as first-class
// snapshot entries so rules targeting child types still fire.
func TranslateARM(tpl *ARMTemplate, pseudoSub, pseudoTenant string) *models.AzureSnapshot {
	snap := &models.AzureSnapshot{
		SubscriptionID:     pseudoSub,
		SubscriptionName:   "arm-template",
		TenantID:           pseudoTenant,
		ScanTime:           time.Now().UTC(),
		CollectionMode:     "iac",
		DefenderPlans:      map[string]string{},
		DiagnosticSettings: map[string]bool{},
	}
	if tpl == nil {
		return snap
	}
	for _, r := range tpl.Resources {
		translateARMResource(snap, r, "")
	}
	return snap
}

// translateARMResource recursively walks an ARM resource and its
// nested children, emitting one AzureResource per node. The parentName
// argument carries the dotted parent path so a child resource's
// synthetic ID stays unique ("server1/database1" rather than just
// "database1").
func translateARMResource(snap *models.AzureSnapshot, r ARMResource, parentName string) {
	if r.Type == "" {
		return
	}
	name := r.Name
	if parentName != "" {
		name = parentName + "/" + name
	}

	// Synthesise a stable resource ID from the type + name path. The
	// pseudo-subscription segment matches what Terraform-translated
	// resources look like so rules can't accidentally distinguish
	// ARM-sourced from Terraform-sourced snapshots (they shouldn't —
	// the resource shape is what rules match on).
	synthID := fmt.Sprintf("/subscriptions/%s/providers/%s/%s",
		snap.SubscriptionID, r.Type, name)

	props := r.Properties
	if props == nil {
		props = map[string]interface{}{}
	}

	// Carry Kind + SKU through. SKU may be a string or an object in
	// ARM; stringify objects via their "name" field which is how every
	// ARGUS policy reads it.
	skuStr := ""
	switch s := r.SKU.(type) {
	case string:
		skuStr = s
	case map[string]interface{}:
		if n, ok := s["name"].(string); ok {
			skuStr = n
		} else if t, ok := s["tier"].(string); ok {
			skuStr = t
		}
	}

	snap.Resources = append(snap.Resources, models.AzureResource{
		ID:            synthID,
		Name:          name,
		Type:          r.Type,
		Kind:          r.Kind,
		Location:      r.Location,
		ResourceGroup: extractResourceGroup(props),
		Properties:    props,
		Tags:          r.Tags,
		SKU:           skuStr,
	})

	// Walk nested child resources. Bicep's `resource foo 'Microsoft.Sql/servers/databases'`
	// declarations land here when compiled down.
	for _, child := range r.NestedResources {
		translateARMResource(snap, child, name)
	}
}

// extractResourceGroup does a best-effort resource group extraction.
// ARM templates don't carry resource_group_name the way Terraform does
// — the deployment itself is scoped to an RG — so we look for a
// "resourceGroupName" hint the user may have left in properties, or
// fall back to empty string. Rules that require an RG value handle
// empty-string gracefully (they skip scope-partitioned checks).
func extractResourceGroup(props map[string]interface{}) string {
	if v, ok := props["resourceGroupName"].(string); ok {
		return v
	}
	if v, ok := props["resource_group_name"].(string); ok {
		return v
	}
	return ""
}

// ScanARMBytes runs the full IaC pipeline against ARM template JSON.
// Returns a Result carrying the translated snapshot, the findings
// filtered to in-template scope, and severity counts.
//
// We build an in-template filter by collecting every synthesised
// resource ID we emitted, then keeping only findings whose ResourceID
// matches. This mirrors the Terraform-side filterToPlanScope so
// ARM-sourced findings can't accidentally include tenant-scope rules
// that fired against the empty identity snapshot.
func ScanARMBytes(payload []byte, pseudoSub, pseudoTenant string) (*Result, error) {
	tpl, err := ParseARMTemplate(payload)
	if err != nil {
		return nil, err
	}
	snap := TranslateARM(tpl, pseudoSub, pseudoTenant)

	eng, err := newEngineForIaC()
	if err != nil {
		return nil, err
	}
	allFindings, err := eng.Evaluate(snap, "all")
	if err != nil {
		return nil, fmt.Errorf("evaluate policies: %w", err)
	}
	findings := filterToARMScope(allFindings, snap)

	res := &Result{
		Snapshot: snap,
		Findings: findings,
		Chains:   correlateIaCChains(findings, snap),
	}
	countSeverity(&res.Counts, findings)
	return res, nil
}

// filterToARMScope keeps findings whose resource ID matches one the
// translator emitted. Equivalent to filterToPlanScope for Terraform
// but indexed on synthesised IDs rather than terraform addresses.
func filterToARMScope(findings []models.Finding, snap *models.AzureSnapshot) []models.Finding {
	owned := make(map[string]struct{}, len(snap.Resources))
	for _, r := range snap.Resources {
		owned[strings.ToLower(r.ID)] = struct{}{}
	}
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if _, ok := owned[strings.ToLower(f.ResourceID)]; ok {
			out = append(out, f)
			continue
		}
		// Match on name suffix as a fallback (for rules that reset
		// ResourceID to just the resource name).
		for rid := range owned {
			if strings.HasSuffix(rid, "/"+strings.ToLower(f.ResourceName)) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// countSeverity tallies findings by severity bucket.
func countSeverity(c *SeverityCounts, findings []models.Finding) {
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			c.Critical++
		case "HIGH":
			c.High++
		case "MEDIUM":
			c.Medium++
		case "LOW":
			c.Low++
		}
	}
}
