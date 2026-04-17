package iac

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Format identifies the IaC artifact we're scanning. The scanner
// dispatches to a format-specific parser based on the value returned
// by DetectFormat. New formats (Pulumi, CDKTF, etc.) slot in by
// defining a new constant, teaching DetectFormat to recognise their
// envelope, and adding a parser.
type Format string

const (
	FormatUnknown    Format = ""
	FormatTerraform  Format = "terraform-plan"
	FormatARM        Format = "arm-template"
	FormatBicep      Format = "bicep"
	FormatARMWhatIf  Format = "arm-whatif"
)

// DetectFormat reads enough of the JSON payload to classify its shape
// and returns the corresponding Format. It never consumes more than
// the top-level object's keys so malformed or huge files fail fast
// before translation begins.
//
// Heuristics, in priority order:
//
//  1. `format_version` + `resource_changes` → Terraform plan JSON
//     (output of `terraform show -json plan.out`).
//  2. `changes` is an array whose elements have `resourceId` +
//     `changeType` → ARM what-if output
//     (`az deployment group what-if --output json`).
//  3. `$schema` contains "deploymentTemplate" OR top-level object has
//     `resources` with at least one entry bearing a dotted
//     `Microsoft.*` type → ARM template JSON (also what `bicep build`
//     emits; the two are structurally identical).
//  4. Nothing matches → FormatUnknown; caller should surface a clear
//     "unrecognised IaC artifact" error.
//
// The returned byte slice is the full file contents so callers don't
// re-read from the reader. The reader is fully consumed on success.
func DetectFormat(r io.Reader) (Format, []byte, error) {
	payload, err := io.ReadAll(r)
	if err != nil {
		return FormatUnknown, nil, fmt.Errorf("read iac file: %w", err)
	}
	if len(payload) == 0 {
		return FormatUnknown, payload, fmt.Errorf("iac file is empty")
	}

	// Decode just the top-level object — we only need to probe keys.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(payload, &probe); err != nil {
		return FormatUnknown, payload, fmt.Errorf("iac file is not a JSON object: %w", err)
	}

	// --- 1. Terraform plan ---
	if _, hasFV := probe["format_version"]; hasFV {
		if _, hasRC := probe["resource_changes"]; hasRC {
			return FormatTerraform, payload, nil
		}
	}

	// --- 2. ARM what-if output ---
	// `az deployment ... what-if --output json` produces:
	//   {"changes":[{"resourceId":"/subs/.../rg/.../providers/...",
	//                "changeType":"Create"|"Modify"|"Delete"|"NoChange"|"Ignore",
	//                "after":{...}, "before":{...}}]}
	if rawChanges, ok := probe["changes"]; ok {
		var changes []map[string]interface{}
		if err := json.Unmarshal(rawChanges, &changes); err == nil {
			for _, ch := range changes {
				// If any element looks like a what-if change, commit
				// to the format. Cheaper than scanning the whole array.
				if _, hasRID := ch["resourceId"]; hasRID {
					if _, hasCT := ch["changeType"]; hasCT {
						return FormatARMWhatIf, payload, nil
					}
				}
			}
		}
	}

	// --- 3. ARM template (Bicep-compiled JSON is indistinguishable) ---
	// Two signals — either is sufficient:
	//   * $schema mentions deploymentTemplate
	//   * resources[] array with at least one Microsoft.*/X type entry
	if rawSchema, ok := probe["$schema"]; ok {
		var schema string
		_ = json.Unmarshal(rawSchema, &schema)
		if strings.Contains(strings.ToLower(schema), "deploymenttemplate") {
			return FormatARM, payload, nil
		}
	}
	if rawResources, ok := probe["resources"]; ok {
		var resources []map[string]interface{}
		if err := json.Unmarshal(rawResources, &resources); err == nil && len(resources) > 0 {
			for _, r := range resources {
				if t, _ := r["type"].(string); strings.HasPrefix(t, "Microsoft.") {
					return FormatARM, payload, nil
				}
			}
		}
	}

	return FormatUnknown, payload, fmt.Errorf("could not detect IaC format; expected Terraform plan JSON, ARM template, or ARM what-if output")
}

// DetectFormatFromBytes is a convenience wrapper around DetectFormat
// for callers that already hold the file content. The returned byte
// slice is the same slice as the input — kept for symmetry with
// DetectFormat's (format, bytes) return shape so callers can forward
// it to the format-specific parser without an extra conditional.
func DetectFormatFromBytes(payload []byte) (Format, []byte, error) {
	return DetectFormat(strings.NewReader(string(payload)))
}
