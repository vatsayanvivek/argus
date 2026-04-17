package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// SARIFReporter emits a SARIF 2.1.0 document for SCM/IDE integration.
type SARIFReporter struct{}

// NewSARIFReporter creates a new SARIF reporter.
func NewSARIFReporter() *SARIFReporter { return &SARIFReporter{} }

// ---- SARIF 2.1.0 minimal types ----

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifText      `json:"help"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// Generate writes a SARIF 2.1.0 file to outputPath.
func (r *SARIFReporter) Generate(findings []models.Finding, outputPath string) error {
	rules := buildSARIFRules(findings)
	results := buildSARIFResults(findings)

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "ARGUS",
						Version:        "1.0.0",
						InformationURI: "https://github.com/vatsayanvivek/argus",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("sarif reporter: marshal: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("sarif reporter: write %s: %w", outputPath, err)
	}
	return nil
}

// buildSARIFRules builds the rules array, deduplicated by finding ID.
func buildSARIFRules(findings []models.Finding) []sarifRule {
	seen := map[string]models.Finding{}
	for _, f := range findings {
		if _, ok := seen[f.ID]; !ok {
			seen[f.ID] = f
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		f := seen[id]
		help := f.RemediationText
		if help == "" {
			help = f.Description
		}
		rule := sarifRule{
			ID:               f.ID,
			Name:             sarifName(f.ID),
			ShortDescription: sarifText{Text: f.Title},
			FullDescription:  sarifText{Text: nonEmpty(f.Description, f.Title)},
			Help:             sarifText{Text: nonEmpty(help, f.Title)},
			Properties: map[string]any{
				"severity":          strings.ToLower(f.Severity),
				"security-severity": securitySeverity(f.Severity),
				"tags":              ruleTags(f),
			},
		}
		if f.CISRule != "" {
			rule.Properties["cis_rule"] = f.CISRule
		}
		if f.NIST80053Control != "" {
			rule.Properties["nist_800_53_control"] = f.NIST80053Control
		}
		if f.NIST800207Tenet != "" {
			rule.Properties["nist_800_207_tenet"] = f.NIST800207Tenet
		}
		if f.MITRETechnique != "" {
			rule.Properties["mitre_technique"] = f.MITRETechnique
		}
		rules = append(rules, rule)
	}
	return rules
}

// buildSARIFResults builds the results array, one entry per finding.
func buildSARIFResults(findings []models.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		msg := f.Title
		if f.Detail != "" {
			msg = f.Title + " — " + f.Detail
		} else if f.Description != "" {
			msg = f.Title + " — " + f.Description
		}

		uri := f.ResourceID
		if uri == "" {
			uri = f.ResourceName
		}
		if uri == "" {
			uri = "unknown"
		}

		props := map[string]any{
			"resource_type":  f.ResourceType,
			"resource_name":  f.ResourceName,
			"resource_group": f.ResourceGroup,
			"location":       f.Location,
			"pillar":         f.Pillar,
		}
		if len(f.ParticipatesInChains) > 0 {
			props["chain_ids"] = f.ParticipatesInChains
		}
		if f.BlastRadius != "" {
			props["blast_radius"] = f.BlastRadius
		}
		if f.MITRETechnique != "" {
			props["mitre_technique"] = f.MITRETechnique
		}
		if f.MITRETactic != "" {
			props["mitre_tactic"] = f.MITRETactic
		}
		if f.ChainRole != "" {
			props["chain_role"] = f.ChainRole
		}

		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: msg},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: uri},
					},
				},
			},
			Properties: props,
		})
	}
	return results
}

// sarifLevel maps finding severity to SARIF level.
func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "none"
	}
}

// securitySeverity returns the GitHub-compatible security-severity score.
func securitySeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "8.0"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "2.0"
	default:
		return "0.0"
	}
}

// sarifName builds a CamelCase rule name from an ID like "argus.cis.1_1".
func sarifName(id string) string {
	if id == "" {
		return "ArgusRule"
	}
	parts := strings.FieldsFunc(id, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '/'
	})
	var out strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		out.WriteString(strings.ToUpper(p[:1]))
		if len(p) > 1 {
			out.WriteString(p[1:])
		}
	}
	if out.Len() == 0 {
		return "ArgusRule"
	}
	return out.String()
}

func ruleTags(f models.Finding) []string {
	tags := []string{"security", "cloud", "azure"}
	if f.Pillar != "" {
		tags = append(tags, "zero-trust", strings.ToLower(f.Pillar))
	}
	if f.Source != "" {
		tags = append(tags, f.Source)
	}
	if len(f.ParticipatesInChains) > 0 {
		tags = append(tags, "attack-chain")
	}
	return tags
}

func nonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
