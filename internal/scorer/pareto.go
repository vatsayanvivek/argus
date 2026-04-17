package scorer

import (
	"sort"
	"strings"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/models"
)

// ComputeQuickWins produces the Pareto remediation roadmap for a scan.
// It returns up to `limit` rules ordered so that fixing them yields
// the largest reduction in attack-chain count and overall score for
// the smallest engineering effort.
//
// Algorithm:
//  1. Group findings by rule ID. Each rule becomes one candidate.
//  2. For each rule, count the unique chains it participates in.
//  3. Compute the "score impact" — what the overall score would
//     improve by if every finding for this rule were resolved.
//     We compute this by:
//       a. Calling Score() once to get the baseline overall score.
//       b. Removing all findings with this rule ID and re-scoring.
//       c. The delta is the score impact.
//  4. Pull effort hours from the remediation CSV via the benchmark
//     loader. If the loader is nil or doesn't have the rule, default
//     to 4 hours (the median for routine misconfigurations).
//  5. Sort by (chains_broken DESC, score_impact DESC, effort_hours ASC).
//  6. Return the top `limit` items.
//
// The result is intentionally rule-level, not finding-level. A
// customer with 13 App Registrations holding dangerous Graph perms
// gets ONE Quick Win item ("Fix zt_id_011 across 13 resources")
// rather than 13 separate items.
func ComputeQuickWins(
	findings []models.Finding,
	chains []models.AttackChain,
	snapshot *models.AzureSnapshot,
	loader *benchmark.BenchmarkLoader,
	limit int,
) []models.QuickWinItem {
	if limit <= 0 {
		limit = 5
	}
	if len(findings) == 0 {
		return nil
	}

	// 1. Group findings by rule.
	byRule := make(map[string][]models.Finding)
	for _, f := range findings {
		byRule[f.ID] = append(byRule[f.ID], f)
	}

	// 2. Build rule-id → list of chain IDs the rule participates in.
	ruleChains := make(map[string]map[string]bool)
	for _, ch := range chains {
		for _, trigger := range ch.TriggerFindings {
			if ruleChains[trigger] == nil {
				ruleChains[trigger] = map[string]bool{}
			}
			ruleChains[trigger][ch.ID] = true
		}
	}

	// 3. Baseline score.
	scorer := NewScorer()
	baseline := scorer.Score(findings, chains, snapshot)
	baselineScore := baseline.OverallScore

	// 4. For each rule, compute the score impact of removing it.
	candidates := make([]models.QuickWinItem, 0, len(byRule))
	for ruleID, ruleFindings := range byRule {
		// Build the "what if we fix this" finding set.
		remaining := make([]models.Finding, 0, len(findings)-len(ruleFindings))
		for _, f := range findings {
			if f.ID != ruleID {
				remaining = append(remaining, f)
			}
		}
		// Recompute chains for the remaining findings — a fix that
		// breaks a chain must remove that chain from the score model.
		// We approximate by filtering chains whose trigger set is no
		// longer satisfied. For simplicity we just drop any chain
		// where the removed rule was a trigger.
		remainingChains := make([]models.AttackChain, 0, len(chains))
		for _, ch := range chains {
			triggered := true
			for _, trig := range ch.TriggerFindings {
				if trig == ruleID {
					triggered = false
					break
				}
			}
			if triggered {
				remainingChains = append(remainingChains, ch)
			}
		}

		alt := scorer.Score(remaining, remainingChains, snapshot)
		impact := alt.OverallScore - baselineScore
		if impact < 0 {
			impact = 0
		}

		// Effort hours from remediation CSV (default 4).
		effort := 4
		requiresLicense := false
		if loader != nil {
			if rem, ok := loader.Remediation[ruleID]; ok {
				if rem.EffortHours > 0 {
					effort = rem.EffortHours
				}
				// Heuristic: any remediation that mentions "Defender",
				// "Standard", or "Premium" likely requires a paid SKU.
				rt := strings.ToLower(rem.RemediationText)
				if strings.Contains(rt, "defender") ||
					strings.Contains(rt, "standard tier") ||
					strings.Contains(rt, "premium") {
					requiresLicense = true
				}
			}
		}

		// Affected unique resources.
		uniqueRes := map[string]bool{}
		for _, f := range ruleFindings {
			uniqueRes[f.ResourceID] = true
		}

		// Chain IDs (sorted for deterministic output).
		chainIDs := make([]string, 0, len(ruleChains[ruleID]))
		for cid := range ruleChains[ruleID] {
			chainIDs = append(chainIDs, cid)
		}
		sort.Strings(chainIDs)

		candidates = append(candidates, models.QuickWinItem{
			RuleID:            ruleID,
			Title:             ruleFindings[0].Title,
			Severity:          ruleFindings[0].Severity,
			Pillar:            ruleFindings[0].Pillar,
			ChainsBroken:      len(ruleChains[ruleID]),
			ChainIDs:          chainIDs,
			ScoreImpact:       round1(impact),
			EffortHours:       effort,
			AffectedResources: len(uniqueRes),
			RequiresLicense:   requiresLicense,
		})
	}

	// 5. Sort: chains broken DESC, score impact DESC, effort ASC.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].ChainsBroken != candidates[j].ChainsBroken {
			return candidates[i].ChainsBroken > candidates[j].ChainsBroken
		}
		if candidates[i].ScoreImpact != candidates[j].ScoreImpact {
			return candidates[i].ScoreImpact > candidates[j].ScoreImpact
		}
		if candidates[i].EffortHours != candidates[j].EffortHours {
			return candidates[i].EffortHours < candidates[j].EffortHours
		}
		// Tiebreaker: stable rule ID order.
		return candidates[i].RuleID < candidates[j].RuleID
	})

	// 6. Trim to limit.
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}
