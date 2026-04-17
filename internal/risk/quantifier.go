package risk

import (
	"math"
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// -------------------------------------------------------------------------
// Structs
// -------------------------------------------------------------------------

// RiskReport is the top-level output of the FAIR-based risk quantification.
// It is designed to give CISOs a defensible, dollar-denominated view of
// residual cyber risk so they can justify remediation budgets.
type RiskReport struct {
	TotalAnnualizedRisk    float64            `json:"total_annualized_risk"`
	Currency               string             `json:"currency"`
	RiskByChain            []ChainRisk        `json:"risk_by_chain"`
	RiskByPillar           map[string]float64 `json:"risk_by_pillar"`
	TopRemediations        []RemediationROI   `json:"top_remediations"`
	BreachProbability30Day float64            `json:"breach_probability_30day"`
	BreachProbability90Day float64            `json:"breach_probability_90day"`
}

// ChainRisk is the dollar-denominated risk for one attack chain.
type ChainRisk struct {
	ChainID           string  `json:"chain_id"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity"`
	AnnualizedLoss    float64 `json:"annualized_loss"`
	SingleLossExpect  float64 `json:"single_loss_expectancy"`
	AnnualRateOccur   float64 `json:"annual_rate_of_occurrence"`
	AffectedResources int     `json:"affected_resources"`
}

// RemediationROI ranks a rule fix by risk-reduction return on investment.
type RemediationROI struct {
	RuleID        string   `json:"rule_id"`
	Title         string   `json:"title"`
	FixCost       float64  `json:"fix_cost"`
	RiskReduction float64  `json:"risk_reduction"`
	ROIMultiple   float64  `json:"roi_multiple"`
	ChainsFixed   []string `json:"chains_fixed"`
}

// -------------------------------------------------------------------------
// Constants — simplified FAIR parameters
// -------------------------------------------------------------------------

// baseSLE maps severity to a base Single Loss Expectancy in USD.
var baseSLE = map[string]float64{
	"CRITICAL": 500_000,
	"HIGH":     200_000,
	"MEDIUM":   50_000,
	"LOW":      10_000,
}

// baseARO maps qualitative likelihood to an Annual Rate of Occurrence.
var baseARO = map[string]float64{
	"High":   0.7,
	"Medium": 0.3,
	"Low":    0.1,
}

// costPerHour is the loaded labour rate used for remediation cost estimates.
const costPerHour = 150.0

// defaultEffortHours is the fallback when a finding has no effort estimate.
const defaultEffortHours = 4

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

// Quantify runs the simplified FAIR model over the provided chains,
// findings, and snapshot and returns a dollar-denominated RiskReport.
func Quantify(chains []models.AttackChain, findings []models.Finding, snapshot *models.AzureSnapshot) *RiskReport {
	report := &RiskReport{
		Currency:     "USD",
		RiskByPillar: make(map[string]float64),
	}

	if len(chains) == 0 {
		return report
	}

	// Index findings by ID for fast lookup.
	findingByID := indexFindings(findings)

	// Index finding by rule for remediation analysis.
	findingByRule := indexFindingsByRule(findings)

	// --- Per-chain risk ---
	var totalALE float64
	var maxDailyRate float64

	for _, chain := range chains {
		cr := quantifyChain(chain, findingByID)
		report.RiskByChain = append(report.RiskByChain, cr)
		totalALE += cr.AnnualizedLoss

		// Aggregate into pillar buckets via the chain's trigger findings.
		pillars := chainPillars(chain, findingByID)
		share := cr.AnnualizedLoss / math.Max(float64(len(pillars)), 1)
		for _, p := range pillars {
			report.RiskByPillar[p] += share
		}

		// Track the highest daily rate for breach probability.
		daily := cr.AnnualRateOccur / 365.0
		if daily > maxDailyRate {
			maxDailyRate = daily
		}
	}

	report.TotalAnnualizedRisk = totalALE

	// --- Breach probability ---
	// Uses the complement model: P(breach in N days) = 1 - (1 - daily_rate)^N
	// We use the max daily rate across all chains as the compound daily rate
	// because a single exploitable chain is sufficient.
	report.BreachProbability30Day = breachProbability(maxDailyRate, 30)
	report.BreachProbability90Day = breachProbability(maxDailyRate, 90)

	// --- Remediation ROI (Pareto analysis) ---
	report.TopRemediations = computeRemediationROI(chains, findingByID, findingByRule)

	return report
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

// quantifyChain runs the FAIR model for a single attack chain.
func quantifyChain(chain models.AttackChain, findingByID map[string]models.Finding) ChainRisk {
	sle := sleForSeverity(chain.Severity)

	// Scale SLE by the number of affected resources. Each additional
	// resource adds 10% of the base SLE, capped at 5x the base.
	resourceCount := len(chain.AffectedResources)
	if resourceCount < 1 {
		resourceCount = 1
	}
	scaleFactor := 1.0 + 0.10*float64(resourceCount-1)
	if scaleFactor > 5.0 {
		scaleFactor = 5.0
	}
	sle *= scaleFactor

	aro := aroForLikelihood(chain.Likelihood)
	ale := sle * aro

	return ChainRisk{
		ChainID:           chain.ID,
		Title:             chain.Title,
		Severity:          chain.Severity,
		AnnualizedLoss:    ale,
		SingleLossExpect:  sle,
		AnnualRateOccur:   aro,
		AffectedResources: resourceCount,
	}
}

// sleForSeverity returns the base SLE for the given severity string.
func sleForSeverity(severity string) float64 {
	if v, ok := baseSLE[strings.ToUpper(severity)]; ok {
		return v
	}
	return baseSLE["MEDIUM"] // conservative default
}

// aroForLikelihood returns the ARO for the given qualitative likelihood.
func aroForLikelihood(likelihood string) float64 {
	// Normalize: accept "high", "High", "HIGH", etc.
	normalized := strings.ToUpper(likelihood)
	for k, v := range baseARO {
		if strings.ToUpper(k) == normalized {
			return v
		}
	}
	return baseARO["Medium"] // conservative default
}

// breachProbability calculates P = 1 - (1 - dailyRate)^days, clamped to [0,1].
func breachProbability(dailyRate float64, days int) float64 {
	if dailyRate <= 0 {
		return 0
	}
	if dailyRate >= 1 {
		return 1
	}
	p := 1.0 - math.Pow(1.0-dailyRate, float64(days))
	return math.Min(math.Max(p, 0), 1)
}

// chainPillars returns the unique ZT pillars touched by a chain's trigger
// findings.
func chainPillars(chain models.AttackChain, findingByID map[string]models.Finding) []string {
	seen := map[string]bool{}
	for _, fid := range chain.TriggerFindings {
		if f, ok := findingByID[fid]; ok && f.Pillar != "" {
			seen[f.Pillar] = true
		}
	}
	// Also check steps' EnabledBy for broader pillar coverage.
	for _, step := range chain.Steps {
		if f, ok := findingByID[step.EnabledBy]; ok && f.Pillar != "" {
			seen[f.Pillar] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// computeRemediationROI performs a Pareto analysis: for each unique rule
// that participates in attack chains, estimate the cost to fix and the
// total annualized risk that would be eliminated, then rank by ROI.
func computeRemediationROI(chains []models.AttackChain, findingByID map[string]models.Finding, findingByRule map[string]models.Finding) []RemediationROI {
	// Build a map: ruleID -> set of chain IDs where this rule is in MinimalFixSet or TriggerFindings.
	type ruleInfo struct {
		chainIDs map[string]bool
		finding  models.Finding
	}
	rules := map[string]*ruleInfo{}

	for _, chain := range chains {
		// MinimalFixSet contains the rule IDs that break the chain.
		ruleIDs := chain.MinimalFixSet
		if len(ruleIDs) == 0 {
			// Fallback to trigger findings if no fix set is defined.
			ruleIDs = chain.TriggerFindings
		}
		for _, rid := range ruleIDs {
			ri, ok := rules[rid]
			if !ok {
				ri = &ruleInfo{chainIDs: map[string]bool{}}
				// Try to find the Finding for this rule.
				if f, exists := findingByID[rid]; exists {
					ri.finding = f
				} else if f, exists := findingByRule[rid]; exists {
					ri.finding = f
				}
				rules[rid] = ri
			}
			ri.chainIDs[chain.ID] = true
		}
	}

	// For each chain, pre-compute ALE so we can sum the risk reduction.
	chainALE := map[string]float64{}
	for _, chain := range chains {
		cr := quantifyChain(chain, findingByID)
		chainALE[chain.ID] = cr.AnnualizedLoss
	}

	var results []RemediationROI
	for ruleID, ri := range rules {
		var riskReduction float64
		chainList := make([]string, 0, len(ri.chainIDs))
		for cid := range ri.chainIDs {
			riskReduction += chainALE[cid]
			chainList = append(chainList, cid)
		}
		sort.Strings(chainList)

		effortHours := ri.finding.EstimatedEffortHours
		if effortHours <= 0 {
			effortHours = defaultEffortHours
		}
		fixCost := float64(effortHours) * costPerHour

		roi := 0.0
		if fixCost > 0 {
			roi = riskReduction / fixCost
		}

		title := ri.finding.Title
		if title == "" {
			title = ruleID
		}

		results = append(results, RemediationROI{
			RuleID:        ruleID,
			Title:         title,
			FixCost:       fixCost,
			RiskReduction: riskReduction,
			ROIMultiple:   roi,
			ChainsFixed:   chainList,
		})
	}

	// Sort descending by ROI multiple (best bang for buck first).
	sort.Slice(results, func(i, j int) bool {
		return results[i].ROIMultiple > results[j].ROIMultiple
	})

	// Cap at top 20 for readability.
	if len(results) > 20 {
		results = results[:20]
	}

	return results
}

// indexFindings builds a lookup map from finding ID to Finding.
func indexFindings(findings []models.Finding) map[string]models.Finding {
	m := make(map[string]models.Finding, len(findings))
	for _, f := range findings {
		m[f.ID] = f
	}
	return m
}

// indexFindingsByRule builds a lookup map from CISRule to Finding.
// When multiple findings share the same CISRule the first one wins.
func indexFindingsByRule(findings []models.Finding) map[string]models.Finding {
	m := make(map[string]models.Finding, len(findings))
	for _, f := range findings {
		if f.CISRule != "" {
			if _, exists := m[f.CISRule]; !exists {
				m[f.CISRule] = f
			}
		}
	}
	return m
}
