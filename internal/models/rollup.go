package models

import "time"

// SubscriptionScanResult is the per-subscription output produced by a
// multi-subscription (org-wide) scan. It carries everything needed to
// build a tenant-level rollup view: the score, all findings, all
// chains, and any error that prevented the scan from completing.
type SubscriptionScanResult struct {
	SubscriptionID   string         `json:"subscription_id"`
	SubscriptionName string         `json:"subscription_name"`
	Findings         []Finding      `json:"findings"`
	Chains           []AttackChain  `json:"chains"`
	Score            *ZTScoreReport `json:"score"`
	Error            string         `json:"error,omitempty"`
}

// TenantRollupReport is the aggregated view of a tenant-wide scan.
// It is produced by the org-wide scan command and consumed by the
// reporters when generating the executive HTML / JSON view across
// every subscription.
type TenantRollupReport struct {
	TenantID            string                   `json:"tenant_id"`
	ScanTime            time.Time                `json:"scan_time"`
	TotalSubscriptions  int                      `json:"total_subscriptions"`
	SubscriptionResults []SubscriptionScanResult `json:"subscription_results"`
	TenantOverallScore  float64                  `json:"tenant_overall_score"`
	TenantGrade         string                   `json:"tenant_grade"`
	WorstSubscription   string                   `json:"worst_subscription"`
	BestSubscription    string                   `json:"best_subscription"`
	CriticalChainCount  int                      `json:"critical_chain_count"`
	TotalChains         int                      `json:"total_chains"`
	FindingsBySeverity  map[string]int           `json:"findings_by_severity"`
}

// AllFindings flattens findings across every subscription, prefixing
// nothing — callers can filter by SubscriptionID via the
// SubscriptionResults slice.
func (r *TenantRollupReport) AllFindings() []Finding {
	out := make([]Finding, 0)
	for _, sr := range r.SubscriptionResults {
		out = append(out, sr.Findings...)
	}
	return out
}

// AllChains flattens chains across every subscription.
func (r *TenantRollupReport) AllChains() []AttackChain {
	out := make([]AttackChain, 0)
	for _, sr := range r.SubscriptionResults {
		out = append(out, sr.Chains...)
	}
	return out
}
