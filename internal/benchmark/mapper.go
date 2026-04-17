package benchmark

import (
	"fmt"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// EnrichFinding mutates the given finding in place, filling in human
// context pulled from the benchmark tables: CIS metadata, NIST control
// mapping, MITRE technique details, Zero Trust tenet description, and
// concrete remediation snippets. It is safe to call on a finding that
// was already partially enriched by the OPA policy itself — existing
// non-empty fields are preserved.
func EnrichFinding(f *models.Finding, l *BenchmarkLoader) {
	if f == nil || l == nil {
		return
	}

	// ---- CIS benchmark metadata ------------------------------------
	if f.CISRule != "" {
		if rule, ok := l.CISRules[f.CISRule]; ok {
			if f.CISLevel == "" {
				f.CISLevel = rule.Level
			}
			if f.Description == "" {
				f.Description = rule.Description
			}
			if f.Title == "" {
				f.Title = rule.Title
			}
			if f.NIST80053Control == "" && rule.NIST80053 != "" {
				f.NIST80053Control = rule.NIST80053
			}
			if f.NIST800207Tenet == "" && rule.NIST800207Tenet != "" {
				f.NIST800207Tenet = rule.NIST800207Tenet
			}
		}
	}

	// ---- NIST 800-53 crosswalk -------------------------------------
	if f.NIST80053Control == "" && f.CISRule != "" {
		if controls, ok := l.Crosswalk[f.CISRule]; ok && len(controls) > 0 {
			f.NIST80053Control = strings.Join(controls, ", ")
		}
	}

	// ---- NIST 800-207 tenet description ----------------------------
	if f.NIST800207Tenet != "" {
		if t, ok := l.ZTTenets[f.NIST800207Tenet]; ok {
			if f.BusinessImpact == "" && t.Description != "" {
				f.BusinessImpact = fmt.Sprintf("Violates Zero Trust tenet %s (%s): %s",
					t.TenetNumber, t.Title, t.Description)
			}
		}
	}

	// ---- MITRE ATT&CK technique ------------------------------------
	if f.MITRETechnique != "" {
		if mt, ok := l.MITREMap[f.MITRETechnique]; ok {
			if f.MITRETactic == "" {
				f.MITRETactic = mt.Tactic
			}
			if f.AttackScenario == "" {
				if mt.AzureRelevance != "" {
					f.AttackScenario = mt.AzureRelevance
				} else {
					f.AttackScenario = mt.Description
				}
			}
		}
	}

	// ---- Remediation details ---------------------------------------
	rem, ok := l.Remediation[f.ID]
	if !ok && f.CISRule != "" {
		rem, ok = l.Remediation[f.CISRule]
	}
	if ok {
		if f.RemediationText == "" {
			f.RemediationText = rem.RemediationText
		}
		if f.RemediationTerraform == "" {
			f.RemediationTerraform = rem.Terraform
		}
		if f.RemediationCLI == "" {
			f.RemediationCLI = rem.AzureCLI
		}
		if f.EstimatedEffortHours == 0 {
			f.EstimatedEffortHours = rem.EffortHours
		}
		if f.BusinessImpact == "" && rem.RiskIfNotFixed != "" {
			f.BusinessImpact = rem.RiskIfNotFixed
		}
	}

	// ---- Default blast-radius derivation from severity -------------
	if f.BlastRadius == "" {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			f.BlastRadius = "Subscription-wide compromise possible"
		case "HIGH":
			f.BlastRadius = "Resource-group compromise possible"
		case "MEDIUM":
			f.BlastRadius = "Single-resource compromise possible"
		default:
			f.BlastRadius = "Limited exposure"
		}
	}
}
