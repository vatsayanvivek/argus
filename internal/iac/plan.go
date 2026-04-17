// Package iac provides pre-deployment security scanning for Azure
// infrastructure-as-code. The primary entry point reads a Terraform plan
// JSON file (produced by `terraform show -json plan.out`) and feeds the
// planned state through the same OPA/Rego engine that argus scan uses,
// so a finding that would fire against the live Azure environment also
// fires against the proposed change before it is applied.
package iac

import (
	"encoding/json"
	"fmt"
	"io"
)

// Plan is the subset of Terraform plan JSON that ARGUS inspects. The full
// schema is much larger; we deliberately decode only what we need so that
// schema additions in future terraform versions do not break the parser.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
}

// ResourceChange is one entry from the top-level `resource_changes` array.
// `Address` uniquely identifies the resource inside the plan ("azurerm_
// storage_account.example" or a module-prefixed variant), `Type` is the
// provider type name, and `Change` carries the action and the planned
// post-apply state.
type ResourceChange struct {
	Address      string `json:"address"`
	ModuleAddr   string `json:"module_address,omitempty"`
	Mode         string `json:"mode"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
	Change       Change `json:"change"`
}

// Change holds the actions terraform intends to perform plus the before/
// after states. For a create or update action `After` contains the planned
// state we want to evaluate.
type Change struct {
	Actions []string               `json:"actions"`
	Before  map[string]interface{} `json:"before"`
	After   map[string]interface{} `json:"after"`
}

// IsCreateOrUpdate reports whether this change introduces or modifies a
// resource. Delete and no-op changes are ignored by the scanner because
// they do not introduce new risk into the environment.
func (c Change) IsCreateOrUpdate() bool {
	for _, a := range c.Actions {
		switch a {
		case "create", "update", "create-then-delete", "delete-then-create":
			return true
		}
	}
	return false
}

// ParsePlan decodes a terraform plan JSON document. The plan is expected
// to have been produced by `terraform show -json <plan-file>`; a raw
// binary plan is not accepted.
func ParsePlan(r io.Reader) (*Plan, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var p Plan
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse terraform plan: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, fmt.Errorf("input does not look like terraform plan JSON (missing format_version)")
	}
	return &p, nil
}

// PlannedResources returns only the changes that create or modify state.
// Everything else (deletes, no-ops, read-only data sources) is filtered out.
func (p *Plan) PlannedResources() []ResourceChange {
	out := make([]ResourceChange, 0, len(p.ResourceChanges))
	for _, rc := range p.ResourceChanges {
		if rc.Mode != "managed" {
			continue
		}
		if !rc.Change.IsCreateOrUpdate() {
			continue
		}
		out = append(out, rc)
	}
	return out
}
