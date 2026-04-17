package scorer

import (
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// Scorer turns raw findings and attack chains into a ZTScoreReport.
// It is intentionally stateless — callers construct one and call Score
// repeatedly if they need to.
type Scorer struct{}

// NewScorer returns a new Scorer. Kept as a constructor to leave room for
// future configuration (custom weights, pluggable grading schemes, etc.).
func NewScorer() *Scorer {
	return &Scorer{}
}

// pillarWeights is the relative contribution of each ZT pillar to the
// overall score. They must sum to 1.0.
var pillarWeights = map[string]float64{
	"Identity":   0.25,
	"Network":    0.25,
	"Workload":   0.20,
	"Data":       0.20,
	"Visibility": 0.10,
}

// severityDeductions is the BASE point penalty applied to a pillar score
// for the FIRST finding of a given severity. Subsequent findings of the
// same severity in the same pillar receive a diminishing penalty so the
// score moves visibly when an operator fixes one of many similar issues.
//
// The diminishing-returns curve is implemented in pillarDeductionFor:
//   1st finding:  100% of base
//   2nd finding:   60% of base
//   3rd finding:   36% of base
//   ...           multiplied by 0.6 each step
//
// Rationale: with the old flat model, fixing 1 of 30 CRITICAL findings
// in a pillar moved the overall score by ~0.2 points and the pillar by
// 20 → 0 was already capped. Customers had no incentive to start fixing
// because progress was invisible. With diminishing returns the FIRST
// fix of any pillar yields the most score recovery, which is exactly
// the right incentive: fix at least one of every kind of finding.
var severityDeductions = map[string]float64{
	"CRITICAL": 20,
	"HIGH":     10,
	"MEDIUM":   5,
	"LOW":      2,
}

// pillarDeductionFor returns the total penalty to apply to a pillar
// when it has `count` findings of the given severity. Uses a geometric
// series with ratio 0.6 so the first finding of a class is the most
// painful and additional ones contribute less, capped at 6× the base
// (the asymptote of the geometric series 1/(1-0.6) = 2.5, multiplied
// by base × 2.4 to keep enough headroom for the cap to actually bite).
func pillarDeductionFor(severity string, count int) float64 {
	if count <= 0 {
		return 0
	}
	base, ok := severityDeductions[strings.ToUpper(severity)]
	if !ok {
		return 0
	}
	const ratio = 0.6
	const maxMultiplier = 2.5 // = 1 / (1 - ratio)
	total := 0.0
	step := 1.0
	for i := 0; i < count; i++ {
		total += step
		step *= ratio
		if total >= maxMultiplier {
			total = maxMultiplier
			break
		}
	}
	return base * total
}

// pillarNISTTenet maps a ZT pillar to its canonical NIST SP 800-207 tenet
// reference for display in PillarScore.NISTTenet.
var pillarNISTTenet = map[string]string{
	"Identity":   "Tenet 6: Authentication and authorization are dynamic",
	"Network":    "Tenet 3: Access granted per-session",
	"Workload":   "Tenet 2: All communication secured regardless of network",
	"Data":       "Tenet 1: All data sources and services are resources",
	"Visibility": "Tenet 7: Collect data to improve security posture",
}

// pillarOrder is the deterministic iteration order used when building the
// pillar score map so that text output is stable.
var pillarOrder = []string{"Identity", "Network", "Workload", "Data", "Visibility"}

// Score runs the full scoring algorithm over the given findings, chains,
// and snapshot, and returns a populated *models.ZTScoreReport.
func (s *Scorer) Score(findings []models.Finding, chains []models.AttackChain, snapshot *models.AzureSnapshot) *models.ZTScoreReport {
	report := &models.ZTScoreReport{
		PillarScores:       make(map[string]models.PillarScore, len(pillarOrder)),
		FindingsBySeverity: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		ChainsBySeverity:   map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		TotalFindings:      len(findings),
		ChainsDetected:     len(chains),
	}

	// Severity counts (raw rule violations).
	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		if _, ok := report.FindingsBySeverity[sev]; !ok {
			report.FindingsBySeverity[sev] = 0
		}
		report.FindingsBySeverity[sev]++
	}

	// Resource-level dedup: count UNIQUE resources per severity bucket.
	// Two rules firing on the same resource (e.g. cis_1_15 and zt_id_011
	// both flagging the same App Registration) count as ONE unique
	// resource even though there are two rule violations.
	uniqueByResource := map[string]map[string]bool{
		"CRITICAL": {},
		"HIGH":     {},
		"MEDIUM":   {},
		"LOW":      {},
	}
	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		if uniqueByResource[sev] == nil {
			uniqueByResource[sev] = map[string]bool{}
		}
		uniqueByResource[sev][f.ResourceID] = true
	}
	report.UniqueCriticalResources = len(uniqueByResource["CRITICAL"])
	report.UniqueHighResources = len(uniqueByResource["HIGH"])
	report.UniqueMediumResources = len(uniqueByResource["MEDIUM"])
	report.UniqueLowResources = len(uniqueByResource["LOW"])
	for _, c := range chains {
		sev := strings.ToUpper(c.Severity)
		if _, ok := report.ChainsBySeverity[sev]; !ok {
			report.ChainsBySeverity[sev] = 0
		}
		report.ChainsBySeverity[sev]++
	}

	// Group findings by pillar.
	findingsByPillar := make(map[string][]models.Finding, len(pillarOrder))
	for _, p := range pillarOrder {
		findingsByPillar[p] = nil
	}
	for _, f := range findings {
		pillar := canonicalPillar(f.Pillar)
		if pillar == "" {
			continue
		}
		findingsByPillar[pillar] = append(findingsByPillar[pillar], f)
	}

	// ---- per-pillar scoring with chain amplification ---------------
	// Work out which chains touch which pillars so we can apply the
	// amplification penalty at most once per chain severity per pillar.
	chainPillarHits := computeChainPillarHits(chains, findings)

	var overall float64
	var weightSum float64

	for _, pillar := range pillarOrder {
		score := 100.0
		pf := findingsByPillar[pillar]

		// Diminishing-returns severity deductions. Group findings by
		// severity, then apply pillarDeductionFor on the count. This
		// rewards fixing the FIRST finding of each severity class
		// substantially while still scaling up for tenants with many
		// problems.
		bySev := map[string]int{}
		for _, f := range pf {
			bySev[strings.ToUpper(f.Severity)]++
		}
		for sev, n := range bySev {
			score -= pillarDeductionFor(sev, n)
		}

		// Chain amplification: for every DISTINCT chain severity that
		// touches this pillar, apply an additional penalty (once).
		seen := map[string]bool{}
		for _, ch := range chainPillarHits[pillar] {
			if seen[ch] {
				continue
			}
			seen[ch] = true
			switch ch {
			case "CRITICAL":
				score -= 10
			case "HIGH":
				score -= 5
			}
		}

		if score < 0 {
			score = 0
		}

		// Pick the highest-severity finding as the "top finding" label.
		top := topFinding(pf)

		ps := models.PillarScore{
			Score:        round1(score),
			Grade:        grade(score),
			FindingCount: len(pf),
			ChainCount:   len(chainPillarHits[pillar]),
			TopFinding:   top,
			NISTTenet:    pillarNISTTenet[pillar],
			TenetStatus:  tenetStatus(score),
		}
		report.PillarScores[pillar] = ps

		w := pillarWeights[pillar]
		overall += score * w
		weightSum += w
	}

	if weightSum > 0 {
		overall = overall / weightSum
	}
	report.OverallScore = round1(overall)
	report.Grade = grade(overall)
	report.MaturityLevel = maturity(overall)

	// ---- CIS coverage ----------------------------------------------
	report.CISCoverage = buildCISCoverage(findings)

	// ---- snapshot-derived tallies ----------------------------------
	if snapshot != nil {
		report.ResourcesScanned = len(snapshot.Resources)
	}

	return report
}

// canonicalPillar normalizes a pillar name so that "identity", "IDENTITY"
// and "Identity" all map to "Identity". Unknown pillars return "".
func canonicalPillar(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "identity":
		return "Identity"
	case "network", "networks":
		return "Network"
	case "workload", "workloads":
		return "Workload"
	case "data":
		return "Data"
	case "visibility", "analytics", "visibility and analytics":
		return "Visibility"
	}
	return ""
}

// computeChainPillarHits returns a map of pillar -> [chain severities that
// touch this pillar]. A chain "touches" a pillar if any finding in its
// TriggerFindings list has that pillar.
func computeChainPillarHits(chains []models.AttackChain, findings []models.Finding) map[string][]string {
	// Build a finding-id -> pillar lookup.
	findingPillar := make(map[string]string, len(findings))
	for _, f := range findings {
		findingPillar[f.ID] = canonicalPillar(f.Pillar)
	}

	out := make(map[string][]string)
	for _, ch := range chains {
		sev := strings.ToUpper(ch.Severity)
		touched := map[string]bool{}
		for _, fid := range ch.TriggerFindings {
			p := findingPillar[fid]
			if p == "" {
				continue
			}
			touched[p] = true
		}
		for p := range touched {
			out[p] = append(out[p], sev)
		}
	}
	return out
}

// topFinding returns a short label for the worst finding in the slice, or
// an empty string if there are no findings.
func topFinding(pf []models.Finding) string {
	if len(pf) == 0 {
		return ""
	}
	rank := func(s string) int {
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
	sorted := make([]models.Finding, len(pf))
	copy(sorted, pf)
	sort.SliceStable(sorted, func(i, j int) bool {
		return rank(sorted[i].Severity) < rank(sorted[j].Severity)
	})
	return sorted[0].Title
}

// grade maps a numeric score to a letter grade.
func grade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// maturity maps a numeric score to a ZT maturity level.
func maturity(score float64) string {
	switch {
	case score >= 90:
		return "Optimal"
	case score >= 75:
		return "Advanced"
	case score >= 60:
		return "Defined"
	case score >= 40:
		return "Developing"
	default:
		return "Initial"
	}
}

// tenetStatus returns the per-pillar tenet satisfaction bucket.
func tenetStatus(score float64) string {
	switch {
	case score >= 80:
		return "SATISFIED"
	case score >= 60:
		return "AT_RISK"
	default:
		return "VIOLATED"
	}
}

// round1 rounds a float to one decimal place.
func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// buildCISCoverage derives a CIS coverage report from the finding list by
// counting which CIS rules have at least one failing finding. The ARGUS
// CIS Azure benchmark 2.0 ships 63 rules in total.
func buildCISCoverage(findings []models.Finding) models.CISCoverageReport {
	const totalRules = 63

	failing := map[string]bool{}
	failingL1 := map[string]bool{}
	failingL2 := map[string]bool{}

	for _, f := range findings {
		if f.CISRule == "" {
			continue
		}
		failing[f.CISRule] = true
		switch strings.ToUpper(f.CISLevel) {
		case "L1":
			failingL1[f.CISRule] = true
		case "L2":
			failingL2[f.CISRule] = true
		}
	}

	// Approximate split: CIS Azure 2.0 has roughly 40 L1 rules and 23 L2.
	const l1Total = 40
	const l2Total = 23

	l1Pass := l1Total - len(failingL1)
	if l1Pass < 0 {
		l1Pass = 0
	}
	l2Pass := l2Total - len(failingL2)
	if l2Pass < 0 {
		l2Pass = 0
	}
	passing := totalRules - len(failing)
	if passing < 0 {
		passing = 0
	}

	return models.CISCoverageReport{
		TotalRules:   totalRules,
		PassingRules: passing,
		FailingRules: len(failing),
		L1PassRate:   rate(l1Pass, l1Total),
		L2PassRate:   rate(l2Pass, l2Total),
		OverallRate:  rate(passing, totalRules),
	}
}

func rate(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return round1(float64(num) / float64(denom) * 100)
}
