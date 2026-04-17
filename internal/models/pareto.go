package models

// QuickWinItem is one entry in the Pareto remediation roadmap.
// Each item represents a single rule (not a single finding) that, if
// fixed, would break one or more attack chains and recover a measurable
// amount of the overall ZT score.
//
// The list is computed AFTER chain correlation so that chain-breaking
// fixes always rank above non-chain fixes, and ordered by:
//   1. ChainsBroken descending  (most chains broken first)
//   2. ScoreImpact descending   (biggest score recovery)
//   3. EffortHours ascending    (cheapest first when tied)
//
// Customers should be able to do "fix the top 5 items in this table"
// and walk away with the highest possible security improvement for
// the least possible engineering investment.
type QuickWinItem struct {
	RuleID            string  `json:"rule_id"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity"`
	Pillar            string  `json:"pillar"`
	ChainsBroken      int     `json:"chains_broken"`
	ChainIDs          []string `json:"chain_ids"`
	ScoreImpact       float64 `json:"score_impact"`
	EffortHours       int     `json:"effort_hours"`
	AffectedResources int     `json:"affected_resources"`
	RequiresLicense   bool    `json:"requires_license"`
}
