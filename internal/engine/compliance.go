package engine

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// CompliancePack is one loaded compliance framework (SOC 2, HIPAA,
// PCI DSS 4.0, ISO 27001). It carries:
//
//   - Framework  — the canonical short name used by the --compliance
//                  CLI flag (e.g. "soc2", "hipaa", "pci-dss-4",
//                  "iso-27001"). Case-insensitive at lookup time.
//   - Controls   — a catalogue of the framework's control IDs with
//                  titles and short descriptions, scoped to the subset
//                  actually referenced by mappings so the embedded
//                  payload stays small.
//   - Mappings   — rule_id → list of control IDs. One rule can cover
//                  multiple controls and vice versa; the relationship
//                  is intentionally many-to-many.
//
// The JSON-on-disk schema is documented in policies/compliance/*.json
// and loaded at engine init alongside the Rego policy tree.
type CompliancePack struct {
	Framework   string                        `json:"framework"`
	DisplayName string                        `json:"display_name"`
	Version     string                        `json:"version"`
	Authority   string                        `json:"authority"`
	ScopeNote   string                        `json:"scope_note"`
	Controls    map[string]ComplianceControl  `json:"controls"`
	Mappings    map[string][]string           `json:"mappings"`
}

// ComplianceControl describes a single control within a framework
// (e.g. SOC 2 CC6.1, HIPAA §164.312(a)(1)).
type ComplianceControl struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// ControlsForRule returns every control ID (across every loaded
// framework) that maps to the given rule ID. The return shape is
// framework → []control_id so callers can render per-framework
// citations without a second lookup.
//
// Unknown rule IDs return an empty map — this is the common case for
// rules that don't yet have a mapping; it is not an error.
func (e *OPAEngine) ControlsForRule(ruleID string) map[string][]string {
	if e == nil || e.compliancePacks == nil {
		return nil
	}
	out := map[string][]string{}
	for fw, pack := range e.compliancePacks {
		if ids, ok := pack.Mappings[ruleID]; ok && len(ids) > 0 {
			// Return a defensive copy so callers can't mutate the
			// engine's map in place.
			ids2 := make([]string, len(ids))
			copy(ids2, ids)
			out[fw] = ids2
		}
	}
	return out
}

// CompliancePack returns the loaded pack for a framework name, or nil
// if that framework isn't known. Framework matching is case-insensitive
// and tolerates a few common aliases ("pci" → "pci-dss-4", "iso27001"
// → "iso-27001").
func (e *OPAEngine) CompliancePack(framework string) *CompliancePack {
	if e == nil || e.compliancePacks == nil {
		return nil
	}
	name := normalizeFramework(framework)
	if pack, ok := e.compliancePacks[name]; ok {
		return pack
	}
	return nil
}

// CompliancePackFrameworks returns the sorted list of framework names
// that are currently loaded. Used by the CLI to render the list of
// accepted --compliance values.
func (e *OPAEngine) CompliancePackFrameworks() []string {
	if e == nil || e.compliancePacks == nil {
		return nil
	}
	out := make([]string, 0, len(e.compliancePacks))
	for k := range e.compliancePacks {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalizeFramework maps common aliases to the canonical framework
// key. The canonical keys match what the JSON payload declares in its
// top-level "framework" field, so user input is tolerant but lookup
// stays unambiguous.
func normalizeFramework(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "pci", "pci4", "pci-4", "pci-dss", "pci-dss-4.0", "pci4.0":
		return "pci-dss-4"
	case "iso", "iso27001", "iso-27001-2022", "iso27001:2022":
		return "iso-27001"
	case "soc", "soc-2":
		return "soc2"
	case "hipaa-security", "hipaa-sr":
		return "hipaa"
	}
	return s
}

// IsComplianceFrameworkLoaded reports whether the given framework name
// (after alias normalisation) matches a loaded pack.
func (e *OPAEngine) IsComplianceFrameworkLoaded(framework string) bool {
	return e.CompliancePack(framework) != nil
}

// loadCompliancePacks walks the embedded policies/compliance/ directory,
// decodes each *.json payload as a CompliancePack, and indexes them by
// framework name. Packs with missing or duplicate framework keys are
// skipped with a warning so a malformed file does not break scan.
func loadCompliancePacks() (map[string]*CompliancePack, error) {
	packs := map[string]*CompliancePack{}
	err := fs.WalkDir(policiesFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		if !strings.Contains(path, "/compliance/") && !strings.HasSuffix(path, "compliance.json") {
			return nil
		}
		content, readErr := policiesFS.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var pack CompliancePack
		if err := json.Unmarshal(content, &pack); err != nil {
			// Skip malformed file; don't fail the whole engine boot.
			return nil
		}
		if pack.Framework == "" {
			return nil
		}
		key := normalizeFramework(pack.Framework)
		if _, dup := packs[key]; dup {
			return nil // first write wins; later duplicates ignored
		}
		packs[key] = &pack
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk compliance packs: %w", err)
	}
	return packs, nil
}

// CoverageReport summarises the compliance coverage for a scan. It
// answers: of the controls in framework F, which ones are *touched* by
// ARGUS rules, and how many of those rules fired on this snapshot?
//
// Callers ask for CoverageReport after a scan completes; the report is
// attached to the JSON/HTML output when --compliance specifies a
// loaded framework.
type CoverageReport struct {
	Framework          string                  `json:"framework"`
	DisplayName        string                  `json:"display_name"`
	Version            string                  `json:"version"`
	TotalControls      int                     `json:"total_controls"`
	CoveredControls    int                     `json:"covered_controls"`
	CoveragePercent    float64                 `json:"coverage_percent"`
	ControlDetails     []ControlCoverageDetail `json:"control_details"`
	UnmappedRules      []string                `json:"unmapped_rules,omitempty"`
}

// ControlCoverageDetail records the per-control picture: which ARGUS
// rules map to it, how many fired, and the highest severity observed.
// Enables a report row like "CC6.1 covered by 8 rules, 3 fired, worst: CRITICAL".
type ControlCoverageDetail struct {
	ControlID       string   `json:"control_id"`
	Title           string   `json:"title"`
	Rules           []string `json:"rules"`
	FiredRules      []string `json:"fired_rules"`
	HighestSeverity string   `json:"highest_severity,omitempty"`
}

// BuildCoverageReport computes coverage metrics for the given framework
// against the findings returned by a scan. firedRuleIDs is the set of
// rule IDs that produced at least one finding; findingSeverityByRuleID
// gives the highest severity emitted per rule so the report can grade
// each control by the worst observed violation.
func (e *OPAEngine) BuildCoverageReport(framework string, firedRuleIDs map[string]bool, findingSeverityByRuleID map[string]string) *CoverageReport {
	pack := e.CompliancePack(framework)
	if pack == nil {
		return nil
	}

	// Build reverse index: control_id → list of rule_ids that map to it.
	ruleByControl := map[string][]string{}
	for rule, controls := range pack.Mappings {
		for _, c := range controls {
			ruleByControl[c] = append(ruleByControl[c], rule)
		}
	}

	report := &CoverageReport{
		Framework:     pack.Framework,
		DisplayName:   pack.DisplayName,
		Version:       pack.Version,
		TotalControls: len(pack.Controls),
	}

	// Sort control IDs lexicographically so the report is deterministic.
	controlIDs := make([]string, 0, len(pack.Controls))
	for id := range pack.Controls {
		controlIDs = append(controlIDs, id)
	}
	sort.Strings(controlIDs)

	for _, cid := range controlIDs {
		ctrl := pack.Controls[cid]
		rules := ruleByControl[cid]
		sort.Strings(rules)
		detail := ControlCoverageDetail{
			ControlID: cid,
			Title:     ctrl.Title,
			Rules:     rules,
		}
		if len(rules) > 0 {
			report.CoveredControls++
			for _, r := range rules {
				if firedRuleIDs[r] {
					detail.FiredRules = append(detail.FiredRules, r)
					sev := findingSeverityByRuleID[r]
					if severityRank2(sev) < severityRank2(detail.HighestSeverity) {
						detail.HighestSeverity = sev
					}
				}
			}
		}
		report.ControlDetails = append(report.ControlDetails, detail)
	}

	if report.TotalControls > 0 {
		report.CoveragePercent = float64(report.CoveredControls) / float64(report.TotalControls) * 100.0
	}

	// Rules that fired but don't map to any control in this framework
	// are informative — they indicate either (a) a rule gap in the
	// mapping or (b) a rule whose subject isn't part of the framework.
	// Report them so the user can ask "why isn't X mapped?".
	mapped := map[string]bool{}
	for rule := range pack.Mappings {
		mapped[rule] = true
	}
	for rule := range firedRuleIDs {
		if !mapped[rule] {
			report.UnmappedRules = append(report.UnmappedRules, rule)
		}
	}
	sort.Strings(report.UnmappedRules)

	return report
}

// severityRank2 duplicates the ordering used by opa.go's severityRank
// (lower rank = more severe) to avoid a cross-file dependency. Kept
// local to the compliance reporter so compliance changes don't ripple
// into other ranking code.
func severityRank2(s string) int {
	switch strings.ToUpper(s) {
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
