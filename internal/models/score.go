package models

// ZTScoreReport is the Zero Trust scoring output.
type ZTScoreReport struct {
	OverallScore       float64                `json:"overall_score"`
	Grade              string                 `json:"grade"`
	MaturityLevel      string                 `json:"maturity_level"`
	PillarScores       map[string]PillarScore `json:"pillar_scores"`
	TotalFindings      int                    `json:"total_findings"`
	FindingsBySeverity map[string]int         `json:"findings_by_severity"`
	ChainsDetected     int                    `json:"chains_detected"`
	ChainsBySeverity   map[string]int         `json:"chains_by_severity"`
	CISCoverage        CISCoverageReport      `json:"cis_coverage"`
	ResourcesScanned   int                    `json:"resources_scanned"`
	DriftAlertsCount   int                    `json:"drift_alerts_count"`
	// Resource-level dedup counts. The same broken control firing on
	// the same resource via two rules (e.g. cis_1_15 + zt_id_011 on
	// the same App Registration) inflates the raw finding count.
	// These fields surface the *unique resource* counts so the report
	// can render "13 unique critical resources (26 rule violations)".
	UniqueCriticalResources int `json:"unique_critical_resources"`
	UniqueHighResources     int `json:"unique_high_resources"`
	UniqueMediumResources   int `json:"unique_medium_resources"`
	UniqueLowResources      int `json:"unique_low_resources"`
}

// PillarScore is the score and metadata for a single ZT pillar.
type PillarScore struct {
	Score        float64 `json:"score"`
	Grade        string  `json:"grade"`
	FindingCount int     `json:"finding_count"`
	ChainCount   int     `json:"chain_count"`
	TopFinding   string  `json:"top_finding"`
	NISTTenet    string  `json:"nist_tenet"`
	TenetStatus  string  `json:"tenet_status"` // SATISFIED | AT_RISK | VIOLATED
}

// CISCoverageReport summarises CIS Azure benchmark coverage.
type CISCoverageReport struct {
	TotalRules    int     `json:"total_rules"`
	PassingRules  int     `json:"passing_rules"`
	FailingRules  int     `json:"failing_rules"`
	L1PassRate    float64 `json:"l1_pass_rate"`
	L2PassRate    float64 `json:"l2_pass_rate"`
	OverallRate   float64 `json:"overall_rate"`
}
