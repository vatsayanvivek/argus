package scorer

import (
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

func mkF(id, sev, pillar string) models.Finding {
	return models.Finding{ID: id, Severity: sev, Pillar: pillar, Title: "test finding " + id}
}

func TestScorer_GradeA(t *testing.T) {
	s := NewScorer()
	report := s.Score([]models.Finding{}, []models.AttackChain{}, &models.AzureSnapshot{})
	if report.OverallScore < 90 {
		t.Errorf("expected score >=90 for empty findings, got %.2f", report.OverallScore)
	}
	if report.Grade != "A" {
		t.Errorf("expected grade A, got %s", report.Grade)
	}
	if report.MaturityLevel != "Optimal" {
		t.Errorf("expected Optimal maturity, got %s", report.MaturityLevel)
	}
	if report.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", report.TotalFindings)
	}
}

func TestScorer_GradeF(t *testing.T) {
	// Under the new diminishing-returns model, a single severity class
	// in a pillar caps at 50 points off — the user can always recover
	// to 50% by fixing the worst issue. To reach Grade F (overall < 40)
	// the environment must have a MIX of severities across MULTIPLE
	// pillars AND chain amplification. This mirrors a real "totally
	// neglected tenant" rather than the synthetic "5 of one severity"
	// case the old test used.
	findings := []models.Finding{}
	for _, p := range []string{"Identity", "Network", "Workload", "Data", "Visibility"} {
		for i := 0; i < 5; i++ {
			findings = append(findings, mkF("t", "CRITICAL", p))
		}
		for i := 0; i < 5; i++ {
			findings = append(findings, mkF("t", "HIGH", p))
		}
		for i := 0; i < 5; i++ {
			findings = append(findings, mkF("t", "MEDIUM", p))
		}
	}
	// Add chain amplification across every pillar.
	chains := []models.AttackChain{
		{ID: "C1", Severity: "CRITICAL", TriggerFindings: []string{"t"}},
		{ID: "C2", Severity: "CRITICAL", TriggerFindings: []string{"t"}},
		{ID: "C3", Severity: "HIGH", TriggerFindings: []string{"t"}},
	}
	s := NewScorer()
	report := s.Score(findings, chains, &models.AzureSnapshot{})
	if report.OverallScore >= 40 {
		t.Errorf("expected score <40, got %.2f", report.OverallScore)
	}
	if report.Grade != "F" {
		t.Errorf("expected grade F, got %s", report.Grade)
	}
}

func TestScorer_PillarWeights(t *testing.T) {
	// One CRITICAL Identity finding -> Identity score = 100 - 20 = 80.
	// All other pillars stay at 100.
	findings := []models.Finding{mkF("t", "CRITICAL", "Identity")}
	s := NewScorer()
	report := s.Score(findings, []models.AttackChain{}, &models.AzureSnapshot{})

	id, ok := report.PillarScores["Identity"]
	if !ok {
		t.Fatal("Identity pillar missing from report")
	}
	if id.Score != 80.0 {
		t.Errorf("Identity should be 80.0, got %.2f", id.Score)
	}
	net, ok := report.PillarScores["Network"]
	if !ok {
		t.Fatal("Network pillar missing from report")
	}
	if net.Score != 100.0 {
		t.Errorf("Network should be 100.0, got %.2f", net.Score)
	}
	// Overall = 80*0.25 + 100*0.25 + 100*0.20 + 100*0.20 + 100*0.10 = 95.
	expected := 95.0
	if report.OverallScore != expected {
		t.Errorf("expected overall %.2f, got %.2f", expected, report.OverallScore)
	}
}

func TestScorer_ChainAmplification(t *testing.T) {
	findings := []models.Finding{mkF("t", "CRITICAL", "Identity")}
	chains := []models.AttackChain{
		{ID: "C1", Severity: "CRITICAL", TriggerFindings: []string{"t"}},
	}
	s := NewScorer()
	withChain := s.Score(findings, chains, &models.AzureSnapshot{})
	withoutChain := s.Score(findings, []models.AttackChain{}, &models.AzureSnapshot{})

	if withChain.OverallScore >= withoutChain.OverallScore {
		t.Errorf("chain amplification should lower overall score: with=%.2f without=%.2f",
			withChain.OverallScore, withoutChain.OverallScore)
	}
	// The affected Identity pillar should also drop.
	idWith := withChain.PillarScores["Identity"].Score
	idWithout := withoutChain.PillarScores["Identity"].Score
	if idWith >= idWithout {
		t.Errorf("Identity pillar should drop when chain amplifies: with=%.2f without=%.2f", idWith, idWithout)
	}
}

func TestScorer_NeverBelowZero(t *testing.T) {
	// Verify that no matter how many findings of every severity we
	// throw at a single pillar, its score never goes negative. The
	// floor stays at 0 — but the new diminishing-returns curve means
	// reaching 0 requires multiple severity classes plus chains, not
	// just N CRITICALs of one kind.
	findings := []models.Finding{}
	for i := 0; i < 50; i++ {
		findings = append(findings, mkF("t", "CRITICAL", "Network"))
		findings = append(findings, mkF("t", "HIGH", "Network"))
		findings = append(findings, mkF("t", "MEDIUM", "Network"))
		findings = append(findings, mkF("t", "LOW", "Network"))
	}
	s := NewScorer()
	report := s.Score(findings, []models.AttackChain{}, &models.AzureSnapshot{})

	net, ok := report.PillarScores["Network"]
	if !ok {
		t.Fatal("Network pillar missing from report")
	}
	if net.Score < 0 {
		t.Errorf("Network score should never go below 0, got %.2f", net.Score)
	}
}

func TestScorer_DiminishingReturnsRewardsFirstFix(t *testing.T) {
	// The new scoring model exists specifically so an operator who
	// fixes the FIRST of N similar findings sees the score move
	// visibly. Verify that fixing 1 of 5 CRITICALs in a pillar
	// produces a measurably higher score than not fixing any.
	with5 := []models.Finding{}
	for i := 0; i < 5; i++ {
		with5 = append(with5, mkF("t", "CRITICAL", "Network"))
	}
	with4 := with5[:4]

	s := NewScorer()
	r5 := s.Score(with5, nil, &models.AzureSnapshot{})
	r4 := s.Score(with4, nil, &models.AzureSnapshot{})

	if r4.OverallScore <= r5.OverallScore {
		t.Errorf("fixing one critical should improve score: 5-criticals=%.2f 4-criticals=%.2f",
			r5.OverallScore, r4.OverallScore)
	}
	delta := r4.OverallScore - r5.OverallScore
	if delta < 0.3 {
		t.Errorf("score delta from fixing one critical should be visible (>=0.3), got %.2f", delta)
	}
}

func TestScorer_MaturityLevels(t *testing.T) {
	cases := []struct {
		name      string
		findings  []models.Finding
		wantGrade string
	}{
		{
			name:      "no_findings",
			findings:  []models.Finding{},
			wantGrade: "A",
		},
		{
			name:      "single_critical_identity", // 95
			findings:  []models.Finding{mkF("t", "CRITICAL", "Identity")},
			wantGrade: "A",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			s := NewScorer()
			r := s.Score(c.findings, nil, &models.AzureSnapshot{})
			if r.Grade != c.wantGrade {
				t.Errorf("%s: expected %s got %s (score=%.1f)", c.name, c.wantGrade, r.Grade, r.OverallScore)
			}
		})
	}
}

func TestScorer_SeverityCounts(t *testing.T) {
	findings := []models.Finding{
		mkF("a", "CRITICAL", "Identity"),
		mkF("b", "HIGH", "Identity"),
		mkF("c", "HIGH", "Network"),
		mkF("d", "MEDIUM", "Data"),
		mkF("e", "LOW", "Visibility"),
	}
	s := NewScorer()
	r := s.Score(findings, nil, &models.AzureSnapshot{})
	if r.FindingsBySeverity["CRITICAL"] != 1 {
		t.Errorf("expected 1 critical, got %d", r.FindingsBySeverity["CRITICAL"])
	}
	if r.FindingsBySeverity["HIGH"] != 2 {
		t.Errorf("expected 2 high, got %d", r.FindingsBySeverity["HIGH"])
	}
	if r.FindingsBySeverity["MEDIUM"] != 1 {
		t.Errorf("expected 1 medium, got %d", r.FindingsBySeverity["MEDIUM"])
	}
	if r.FindingsBySeverity["LOW"] != 1 {
		t.Errorf("expected 1 low, got %d", r.FindingsBySeverity["LOW"])
	}
	if r.TotalFindings != 5 {
		t.Errorf("expected 5 total, got %d", r.TotalFindings)
	}
}

func TestScorer_TenetStatusBuckets(t *testing.T) {
	// No findings -> Identity score 100 -> SATISFIED.
	s := NewScorer()
	r := s.Score(nil, nil, &models.AzureSnapshot{})
	id := r.PillarScores["Identity"]
	if id.TenetStatus != "SATISFIED" {
		t.Errorf("no findings should produce SATISFIED Identity tenet, got %s", id.TenetStatus)
	}

	// One CRITICAL: 100 - 20 = 80 -> SATISFIED (>=80).
	findings := []models.Finding{mkF("a", "CRITICAL", "Identity")}
	r = s.Score(findings, nil, &models.AzureSnapshot{})
	id = r.PillarScores["Identity"]
	if id.TenetStatus != "SATISFIED" {
		t.Errorf("expected SATISFIED for score 80, got %s (score=%.2f)", id.TenetStatus, id.Score)
	}

	// Three CRITICALs: 100 - 20*(1+0.6+0.36) = 100 - 39.2 = 60.8 -> AT_RISK.
	findings = []models.Finding{
		mkF("a", "CRITICAL", "Identity"),
		mkF("b", "CRITICAL", "Identity"),
		mkF("c", "CRITICAL", "Identity"),
	}
	r = s.Score(findings, nil, &models.AzureSnapshot{})
	id = r.PillarScores["Identity"]
	if id.TenetStatus != "AT_RISK" {
		t.Errorf("expected AT_RISK for score ~60.8, got %s (score=%.2f)", id.TenetStatus, id.Score)
	}

	// Mixing CRITICAL+HIGH+MEDIUM pushes well below 60 -> VIOLATED.
	findings = append(findings,
		mkF("d", "CRITICAL", "Identity"),
		mkF("e", "CRITICAL", "Identity"),
		mkF("f", "HIGH", "Identity"),
		mkF("g", "HIGH", "Identity"),
		mkF("h", "MEDIUM", "Identity"),
	)
	r = s.Score(findings, nil, &models.AzureSnapshot{})
	id = r.PillarScores["Identity"]
	if id.TenetStatus != "VIOLATED" {
		t.Errorf("expected VIOLATED for mixed-severity Identity, got %s (score=%.2f)", id.TenetStatus, id.Score)
	}
}

func TestScorer_CISCoverageCounts(t *testing.T) {
	findings := []models.Finding{
		{ID: "cis_1_1", CISRule: "cis_1_1", CISLevel: "L1", Severity: "HIGH", Pillar: "Identity"},
		{ID: "cis_3_1", CISRule: "cis_3_1", CISLevel: "L1", Severity: "HIGH", Pillar: "Data"},
		{ID: "cis_4_1", CISRule: "cis_4_1", CISLevel: "L2", Severity: "HIGH", Pillar: "Data"},
	}
	s := NewScorer()
	r := s.Score(findings, nil, &models.AzureSnapshot{})
	if r.CISCoverage.TotalRules != 63 {
		t.Errorf("expected 63 total rules, got %d", r.CISCoverage.TotalRules)
	}
	if r.CISCoverage.FailingRules != 3 {
		t.Errorf("expected 3 failing rules, got %d", r.CISCoverage.FailingRules)
	}
	if r.CISCoverage.PassingRules != 60 {
		t.Errorf("expected 60 passing rules, got %d", r.CISCoverage.PassingRules)
	}
}
