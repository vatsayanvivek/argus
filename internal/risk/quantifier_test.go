package risk

import (
	"math"
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

// tolerance for floating-point comparisons.
const eps = 0.01

func TestQuantify_BasicChain(t *testing.T) {
	chains := []models.AttackChain{
		{
			ID:         "CHAIN-001",
			Title:      "Privilege Escalation via Stale Admin",
			Severity:   "CRITICAL",
			Likelihood: "High",
			TriggerFindings: []string{"finding-1", "finding-2"},
			AffectedResources: []string{"res-1", "res-2", "res-3"},
			MinimalFixSet: []string{"finding-1"},
			Steps: []models.ChainStep{
				{Number: 1, EnabledBy: "finding-1"},
				{Number: 2, EnabledBy: "finding-2"},
			},
		},
	}
	findings := []models.Finding{
		{ID: "finding-1", Pillar: "Identity", Severity: "CRITICAL", Title: "Stale admin accounts", EstimatedEffortHours: 2},
		{ID: "finding-2", Pillar: "Identity", Severity: "HIGH", Title: "No MFA for admins", EstimatedEffortHours: 4},
	}

	report := Quantify(chains, findings, nil)

	if report.Currency != "USD" {
		t.Errorf("expected currency USD, got %s", report.Currency)
	}
	if len(report.RiskByChain) != 1 {
		t.Fatalf("expected 1 chain risk, got %d", len(report.RiskByChain))
	}

	cr := report.RiskByChain[0]

	// SLE: base $500K * scale factor (1 + 0.10*(3-1)) = 500000 * 1.2 = 600000
	expectedSLE := 600_000.0
	if math.Abs(cr.SingleLossExpect-expectedSLE) > eps {
		t.Errorf("SLE: expected %.2f, got %.2f", expectedSLE, cr.SingleLossExpect)
	}

	// ARO for High = 0.7
	if math.Abs(cr.AnnualRateOccur-0.7) > eps {
		t.Errorf("ARO: expected 0.7, got %.4f", cr.AnnualRateOccur)
	}

	// ALE = 600000 * 0.7 = 420000
	expectedALE := 420_000.0
	if math.Abs(cr.AnnualizedLoss-expectedALE) > eps {
		t.Errorf("ALE: expected %.2f, got %.2f", expectedALE, cr.AnnualizedLoss)
	}

	if cr.AffectedResources != 3 {
		t.Errorf("affected resources: expected 3, got %d", cr.AffectedResources)
	}

	// Total should equal the single chain's ALE.
	if math.Abs(report.TotalAnnualizedRisk-expectedALE) > eps {
		t.Errorf("total annualized risk: expected %.2f, got %.2f", expectedALE, report.TotalAnnualizedRisk)
	}
}

func TestQuantify_PillarAggregation(t *testing.T) {
	chains := []models.AttackChain{
		{
			ID:              "CHAIN-A",
			Severity:        "HIGH",
			Likelihood:      "Medium",
			TriggerFindings: []string{"f-net"},
			AffectedResources: []string{"r1"},
		},
		{
			ID:              "CHAIN-B",
			Severity:        "MEDIUM",
			Likelihood:      "Low",
			TriggerFindings: []string{"f-data"},
			AffectedResources: []string{"r2"},
		},
	}
	findings := []models.Finding{
		{ID: "f-net", Pillar: "Network"},
		{ID: "f-data", Pillar: "Data"},
	}

	report := Quantify(chains, findings, nil)

	// CHAIN-A: SLE=200K*1.0, ARO=0.3 => ALE=60K => Network=60K
	// CHAIN-B: SLE=50K*1.0,  ARO=0.1 => ALE=5K  => Data=5K
	networkRisk := report.RiskByPillar["Network"]
	dataRisk := report.RiskByPillar["Data"]

	if math.Abs(networkRisk-60_000) > eps {
		t.Errorf("Network pillar risk: expected 60000, got %.2f", networkRisk)
	}
	if math.Abs(dataRisk-5_000) > eps {
		t.Errorf("Data pillar risk: expected 5000, got %.2f", dataRisk)
	}
}

func TestQuantify_RemediationROIOrdering(t *testing.T) {
	chains := []models.AttackChain{
		{
			ID:              "CHAIN-1",
			Severity:        "CRITICAL",
			Likelihood:      "High",
			TriggerFindings: []string{"cheap-fix", "expensive-fix"},
			MinimalFixSet:   []string{"cheap-fix", "expensive-fix"},
			AffectedResources: []string{"r1"},
		},
		{
			ID:              "CHAIN-2",
			Severity:        "HIGH",
			Likelihood:      "Medium",
			TriggerFindings: []string{"cheap-fix"},
			MinimalFixSet:   []string{"cheap-fix"},
			AffectedResources: []string{"r2"},
		},
	}
	findings := []models.Finding{
		{ID: "cheap-fix", Title: "Quick Win", EstimatedEffortHours: 1, Pillar: "Identity"},
		{ID: "expensive-fix", Title: "Major Overhaul", EstimatedEffortHours: 40, Pillar: "Network"},
	}

	report := Quantify(chains, findings, nil)

	if len(report.TopRemediations) < 2 {
		t.Fatalf("expected at least 2 remediations, got %d", len(report.TopRemediations))
	}

	// The cheap-fix should have a higher ROI because it costs $150 and
	// eliminates risk from both chains, while expensive-fix costs $6000
	// and only fixes one chain.
	first := report.TopRemediations[0]
	second := report.TopRemediations[1]

	if first.RuleID != "cheap-fix" {
		t.Errorf("expected cheap-fix to be #1 by ROI, got %s", first.RuleID)
	}
	if second.RuleID != "expensive-fix" {
		t.Errorf("expected expensive-fix to be #2 by ROI, got %s", second.RuleID)
	}

	if first.ROIMultiple <= second.ROIMultiple {
		t.Errorf("first ROI (%.2f) should be > second ROI (%.2f)", first.ROIMultiple, second.ROIMultiple)
	}

	// cheap-fix should reference both chains.
	if len(first.ChainsFixed) != 2 {
		t.Errorf("cheap-fix should fix 2 chains, got %d", len(first.ChainsFixed))
	}

	// Fix cost for cheap-fix: 1 hour * $150 = $150
	if math.Abs(first.FixCost-150) > eps {
		t.Errorf("fix cost: expected 150, got %.2f", first.FixCost)
	}
}

func TestQuantify_BreachProbability(t *testing.T) {
	chains := []models.AttackChain{
		{
			ID:              "CHAIN-HIGH",
			Severity:        "CRITICAL",
			Likelihood:      "High",
			AffectedResources: []string{"r1"},
		},
	}

	report := Quantify(chains, nil, nil)

	// daily rate = 0.7 / 365 ~= 0.001918
	// P(30) = 1 - (1 - 0.001918)^30 ~= 0.0559
	// P(90) = 1 - (1 - 0.001918)^90 ~= 0.1588
	if report.BreachProbability30Day < 0.04 || report.BreachProbability30Day > 0.07 {
		t.Errorf("30-day breach probability out of range: %.4f", report.BreachProbability30Day)
	}
	if report.BreachProbability90Day < 0.14 || report.BreachProbability90Day > 0.19 {
		t.Errorf("90-day breach probability out of range: %.4f", report.BreachProbability90Day)
	}

	// 30-day should be less than 90-day.
	if report.BreachProbability30Day >= report.BreachProbability90Day {
		t.Errorf("30-day (%.4f) should be < 90-day (%.4f)",
			report.BreachProbability30Day, report.BreachProbability90Day)
	}
}

func TestQuantify_EmptyInputs(t *testing.T) {
	report := Quantify(nil, nil, nil)

	if report.Currency != "USD" {
		t.Errorf("expected currency USD, got %s", report.Currency)
	}
	if report.TotalAnnualizedRisk != 0 {
		t.Errorf("expected 0 total risk for empty input, got %.2f", report.TotalAnnualizedRisk)
	}
	if len(report.RiskByChain) != 0 {
		t.Errorf("expected 0 chain risks, got %d", len(report.RiskByChain))
	}
	if report.BreachProbability30Day != 0 {
		t.Errorf("expected 0 breach prob for empty input, got %.4f", report.BreachProbability30Day)
	}
	if report.BreachProbability90Day != 0 {
		t.Errorf("expected 0 breach prob for empty input, got %.4f", report.BreachProbability90Day)
	}
	if len(report.TopRemediations) != 0 {
		t.Errorf("expected 0 remediations, got %d", len(report.TopRemediations))
	}
}

func TestBreachProbability_EdgeCases(t *testing.T) {
	// Zero rate should give zero probability.
	if p := breachProbability(0, 30); p != 0 {
		t.Errorf("expected 0 for zero rate, got %.4f", p)
	}

	// Rate >= 1 should give probability 1.
	if p := breachProbability(1.0, 1); p != 1 {
		t.Errorf("expected 1 for rate=1, got %.4f", p)
	}

	// Negative rate should give 0.
	if p := breachProbability(-0.5, 30); p != 0 {
		t.Errorf("expected 0 for negative rate, got %.4f", p)
	}
}

func TestSLEScaleCap(t *testing.T) {
	// With 50 resources the scale factor should be capped at 5x.
	resources := make([]string, 50)
	for i := range resources {
		resources[i] = "r"
	}
	chain := models.AttackChain{
		ID:                "CHAIN-BIG",
		Severity:          "HIGH",
		Likelihood:        "Low",
		AffectedResources: resources,
	}

	cr := quantifyChain(chain, nil)

	// SLE should be 200K * 5.0 = 1M (capped).
	expectedSLE := 1_000_000.0
	if math.Abs(cr.SingleLossExpect-expectedSLE) > eps {
		t.Errorf("SLE with cap: expected %.2f, got %.2f", expectedSLE, cr.SingleLossExpect)
	}
}

func TestQuantify_DefaultEffortHours(t *testing.T) {
	// When a finding has EstimatedEffortHours == 0, the default of 4 hours
	// should be used, giving a fix cost of 4 * $150 = $600.
	chains := []models.AttackChain{
		{
			ID:              "CHAIN-DEF",
			Severity:        "MEDIUM",
			Likelihood:      "Low",
			TriggerFindings: []string{"no-effort"},
			MinimalFixSet:   []string{"no-effort"},
			AffectedResources: []string{"r1"},
		},
	}
	findings := []models.Finding{
		{ID: "no-effort", Title: "Missing config", Pillar: "Data", EstimatedEffortHours: 0},
	}

	report := Quantify(chains, findings, nil)

	if len(report.TopRemediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(report.TopRemediations))
	}
	if math.Abs(report.TopRemediations[0].FixCost-600) > eps {
		t.Errorf("default fix cost: expected 600, got %.2f", report.TopRemediations[0].FixCost)
	}
}
