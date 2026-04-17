package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// JSONReporter writes a comprehensive machine-readable report.
type JSONReporter struct {
	quickWins               []models.QuickWinItem
	graphPermissionsLimited bool
	graphPermissionsMissing []string
	// complianceCoverage carries per-framework coverage reports
	// computed by the engine against the current scan's findings. Keyed
	// by framework short name ("soc2", "hipaa", "pci-dss-4",
	// "iso-27001"). Emitted only when populated so backwards
	// compatibility with consumers that parsed pre-v1.6 JSON is
	// preserved.
	complianceCoverage map[string]interface{}
}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter() *JSONReporter { return &JSONReporter{} }

// SetQuickWins attaches the Pareto remediation roadmap so it appears
// in the JSON output.
func (r *JSONReporter) SetQuickWins(items []models.QuickWinItem) {
	r.quickWins = items
}

// SetGraphPermissionsWarning records that the scanning identity did
// not have full Microsoft Graph access, so the JSON consumer can flag
// the partial-scan caveat.
func (r *JSONReporter) SetGraphPermissionsWarning(limited bool, missing []string) {
	r.graphPermissionsLimited = limited
	r.graphPermissionsMissing = missing
}

// SetComplianceCoverage attaches one or more compliance-framework
// coverage reports to the JSON output. The value is a plain
// map[framework]->report-struct; the JSON marshaller serialises it
// through normally without the reporter knowing the exact report
// schema. Decoupling here keeps engine.CoverageReport out of the
// reporter package's type graph.
func (r *JSONReporter) SetComplianceCoverage(coverage map[string]interface{}) {
	r.complianceCoverage = coverage
}

type jsonMetadata struct {
	Tool             string `json:"tool"`
	Version          string `json:"version"`
	GeneratedAt      string `json:"generated_at"`
	SubscriptionID   string `json:"subscription_id"`
	SubscriptionName string `json:"subscription_name"`
	TenantID         string `json:"tenant_id"`
	ScanTime         string `json:"scan_time"`
	CollectionMode   string `json:"collection_mode"`
}

type jsonSummary struct {
	TotalFindings    int            `json:"total_findings"`
	ChainsDetected   int            `json:"chains_detected"`
	CriticalFindings int            `json:"critical_findings"`
	HighFindings     int            `json:"high_findings"`
	MediumFindings   int            `json:"medium_findings"`
	LowFindings      int            `json:"low_findings"`
	ChainsBySeverity map[string]int `json:"chains_by_severity"`
	DriftCount       int            `json:"drift_count"`
}

type jsonReport struct {
	Metadata                jsonMetadata           `json:"metadata"`
	Score                   *models.ZTScoreReport  `json:"score"`
	Summary                 jsonSummary            `json:"summary"`
	AttackChains            []models.AttackChain   `json:"attack_chains"`
	Findings                []models.Finding       `json:"findings"`
	DriftFindings           []models.DriftFinding  `json:"drift_findings,omitempty"`
	QuickWins               []models.QuickWinItem  `json:"quick_wins,omitempty"`
	GraphPermissionsLimited bool                   `json:"graph_permissions_limited,omitempty"`
	GraphPermissionsMissing []string               `json:"graph_permissions_missing,omitempty"`
	ComplianceCoverage      map[string]interface{} `json:"compliance_coverage,omitempty"`
}

// Generate writes the comprehensive JSON report to outputPath.
func (r *JSONReporter) Generate(
	snapshot *models.AzureSnapshot,
	findings []models.Finding,
	chains []models.AttackChain,
	score *models.ZTScoreReport,
	driftFindings []models.DriftFinding,
	outputPath string,
) error {
	meta := jsonMetadata{
		Tool:        "ARGUS",
		Version:     "1.0.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if snapshot != nil {
		meta.SubscriptionID = snapshot.SubscriptionID
		meta.SubscriptionName = snapshot.SubscriptionName
		meta.TenantID = snapshot.TenantID
		meta.ScanTime = snapshot.ScanTime.UTC().Format(time.RFC3339)
		meta.CollectionMode = snapshot.CollectionMode
	}

	summary := jsonSummary{
		TotalFindings:    len(findings),
		ChainsDetected:   len(chains),
		ChainsBySeverity: map[string]int{},
		DriftCount:       len(driftFindings),
	}
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			summary.CriticalFindings++
		case "HIGH":
			summary.HighFindings++
		case "MEDIUM":
			summary.MediumFindings++
		case "LOW":
			summary.LowFindings++
		}
	}
	for _, c := range chains {
		summary.ChainsBySeverity[strings.ToUpper(c.Severity)]++
	}

	report := jsonReport{
		Metadata:                meta,
		Score:                   score,
		Summary:                 summary,
		AttackChains:            chains,
		Findings:                findings,
		QuickWins:               r.quickWins,
		GraphPermissionsLimited: r.graphPermissionsLimited || (snapshot != nil && snapshot.GraphPermissionsLimited),
	}
	if r.graphPermissionsLimited {
		report.GraphPermissionsMissing = r.graphPermissionsMissing
	} else if snapshot != nil && snapshot.GraphPermissionsLimited {
		report.GraphPermissionsMissing = snapshot.GraphPermissionsMissing
	}
	if len(driftFindings) > 0 {
		report.DriftFindings = driftFindings
	}
	if len(r.complianceCoverage) > 0 {
		report.ComplianceCoverage = r.complianceCoverage
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("json reporter: marshal: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("json reporter: write %s: %w", outputPath, err)
	}
	return nil
}
