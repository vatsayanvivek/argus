package iac

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// WhatIfOutput models the JSON shape produced by
// `az deployment group what-if --output json`. We decode only the
// fields ARGUS inspects; the full schema is larger and includes
// properties-before / properties-after delta markers we don't need.
type WhatIfOutput struct {
	Changes []WhatIfChange `json:"changes"`
	// Older versions of az emit the result under a "properties" key
	// instead of at the top level. We opportunistically handle both by
	// attempting the top-level decode first and falling back to
	// {"properties": {"changes": [...]}} if Changes is empty.
	Properties *struct {
		Changes []WhatIfChange `json:"changes"`
	} `json:"properties,omitempty"`
}

// WhatIfChange is one deployment-change entry. changeType values we
// care about: "Create", "Modify", "Deploy". We ignore "Delete",
// "NoChange", "Ignore" because they either remove risk or introduce
// none.
type WhatIfChange struct {
	ResourceID string                 `json:"resourceId"`
	ChangeType string                 `json:"changeType"`
	After      map[string]interface{} `json:"after"`
	Before     map[string]interface{} `json:"before,omitempty"`
}

// ParseWhatIf decodes ARM what-if JSON. Accepts both the modern
// top-level shape and the legacy {"properties": {...}} envelope.
func ParseWhatIf(payload []byte) (*WhatIfOutput, error) {
	var out WhatIfOutput
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("parse ARM what-if: %w", err)
	}
	if len(out.Changes) == 0 && out.Properties != nil && len(out.Properties.Changes) > 0 {
		out.Changes = out.Properties.Changes
	}
	if len(out.Changes) == 0 {
		return nil, fmt.Errorf("ARM what-if output contains no changes[]")
	}
	return &out, nil
}

// TranslateWhatIf produces an AzureSnapshot from an ARM what-if
// output. Each Create/Modify/Deploy change is emitted as a resource
// snapshot entry; Delete and NoChange changes are skipped because
// they either remove attack surface or leave it unchanged.
//
// The After state is the planned post-deployment shape — that's what
// rules need to evaluate. For Modify changes the After state already
// represents the merged result (existing resource + requested change)
// because the Azure ARM API computes the diff server-side before
// returning what-if output.
func TranslateWhatIf(w *WhatIfOutput, pseudoSub, pseudoTenant string) *models.AzureSnapshot {
	snap := &models.AzureSnapshot{
		SubscriptionID:     pseudoSub,
		SubscriptionName:   "arm-whatif",
		TenantID:           pseudoTenant,
		ScanTime:           time.Now().UTC(),
		CollectionMode:     "iac",
		DefenderPlans:      map[string]string{},
		DiagnosticSettings: map[string]bool{},
	}
	if w == nil {
		return snap
	}
	for _, ch := range w.Changes {
		if !isIntroducingChange(ch.ChangeType) {
			continue
		}
		resource := whatIfChangeToResource(ch)
		if resource.Type == "" {
			continue
		}
		snap.Resources = append(snap.Resources, resource)
	}
	return snap
}

// isIntroducingChange reports whether a what-if changeType adds or
// modifies attack surface. Microsoft's what-if documents the
// changeType enum as: Create | Deploy | Modify | NoChange | Ignore |
// Delete | Unsupported. We count the first three (since Deploy and
// Create both materialise resources and Modify rewrites them) and
// ignore the rest.
func isIntroducingChange(ct string) bool {
	switch strings.ToLower(ct) {
	case "create", "deploy", "modify":
		return true
	}
	return false
}

// whatIfChangeToResource builds an AzureResource from a what-if
// change. We recover the ARM type from the resourceId path — what-if
// omits the explicit "type" field — and adopt the After state as
// the resource's property shape. Resources whose type can't be parsed
// (shouldn't happen with a valid what-if response) are returned with
// Type="" so the caller can filter them out.
func whatIfChangeToResource(ch WhatIfChange) models.AzureResource {
	armType := armTypeFromResourceID(ch.ResourceID)
	name := resourceNameFromID(ch.ResourceID)
	rg := resourceGroupFromID(ch.ResourceID)

	props := ch.After
	if props == nil {
		props = map[string]interface{}{}
	}

	// Pull common top-level fields out of After if the rule engine
	// will expect them there.
	location, _ := props["location"].(string)
	kind, _ := props["kind"].(string)
	tags := map[string]string{}
	if raw, ok := props["tags"].(map[string]interface{}); ok {
		for k, v := range raw {
			if s, ok := v.(string); ok {
				tags[k] = s
			}
		}
	}

	// Extract the nested properties block which holds the
	// resource-specific configuration the rules match on. ARM places
	// the real config under "properties" inside the resource object.
	innerProps, _ := props["properties"].(map[string]interface{})
	if innerProps == nil {
		innerProps = map[string]interface{}{}
	}
	// Merge top-level metadata into the properties map so rules that
	// look for "location" or "kind" at the top level find them.
	for k, v := range props {
		if k == "properties" || k == "tags" {
			continue
		}
		if _, exists := innerProps[k]; !exists {
			innerProps[k] = v
		}
	}

	skuStr := ""
	if skuRaw, ok := props["sku"]; ok {
		switch s := skuRaw.(type) {
		case string:
			skuStr = s
		case map[string]interface{}:
			if n, ok := s["name"].(string); ok {
				skuStr = n
			}
		}
	}

	return models.AzureResource{
		ID:            ch.ResourceID,
		Name:          name,
		Type:          armType,
		Kind:          kind,
		Location:      location,
		ResourceGroup: rg,
		Properties:    innerProps,
		Tags:          tags,
		SKU:           skuStr,
	}
}

// armTypeFromResourceID extracts the canonical Microsoft.X/Y ARM
// type from an Azure resource ID. The ID looks like
// /subscriptions/SID/resourceGroups/RG/providers/Microsoft.X/Y/NAME
// (optionally followed by /childType/childName). We scan from the
// last "providers/" segment and join type+child-type components so
// child resources get their correct ARM type
// (Microsoft.Sql/servers/databases rather than Microsoft.Sql/servers).
func armTypeFromResourceID(id string) string {
	parts := strings.Split(id, "/")
	// Find the last "providers" segment.
	providersIdx := -1
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.EqualFold(parts[i], "providers") {
			providersIdx = i
			break
		}
	}
	if providersIdx < 0 || providersIdx+2 >= len(parts) {
		return ""
	}
	// After "providers" we have: Namespace / Type / Name [/ ChildType / ChildName ...]
	// i.e. provider = parts[providersIdx+1], then alternating Type/Name pairs.
	components := parts[providersIdx+1:]
	if len(components) < 2 {
		return ""
	}
	namespace := components[0]
	// Collect every even-indexed component after the namespace: those are type segments.
	types := []string{components[1]}
	for i := 3; i < len(components); i += 2 {
		types = append(types, components[i])
	}
	return namespace + "/" + strings.Join(types, "/")
}

// resourceNameFromID returns the last path segment of an Azure
// resource ID — the resource's own name.
func resourceNameFromID(id string) string {
	parts := strings.Split(strings.TrimRight(id, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// resourceGroupFromID returns the resource group segment of an Azure
// resource ID (empty when the resource is subscription-scoped).
func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

// ScanWhatIfBytes runs the full IaC pipeline against ARM what-if JSON.
func ScanWhatIfBytes(payload []byte, pseudoSub, pseudoTenant string) (*Result, error) {
	w, err := ParseWhatIf(payload)
	if err != nil {
		return nil, err
	}
	snap := TranslateWhatIf(w, pseudoSub, pseudoTenant)

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
