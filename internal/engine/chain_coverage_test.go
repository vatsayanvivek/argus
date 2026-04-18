package engine

// chain_coverage_test.go validates the attack-chain correlator.
//
// Chains are the core ARGUS differentiator — they stitch multiple findings
// into a realistic end-to-end attack narrative. The correlator has three
// trigger flavours:
//
//   ALL              : every ruleID in TriggerIDs has at least one finding
//   ANY_TWO          : at least two distinct ruleIDs from TriggerIDs fired
//   ANCHOR_PLUS_ONE  : AnchorID fired AND at least one non-anchor trigger fired
//
// These tests synthesise findings directly (bypassing Rego evaluation) and
// verify the correlator's trigger-matching logic. Coverage:
//
//   * ANCHOR_PLUS_ONE positive + negative  (CHAIN-001)
//   * ALL positive + negative              (CHAIN-002)
//   * Participation index correctness      (MarkChainParticipants)
//   * Severity-sorted output               (chains come back severity-first)

import (
	"testing"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// finding builds a minimal Finding that satisfies trigger matching. The
// correlator only looks at ID when matching triggers, but Severity is
// carried through to chain output so we give realistic values.
func finding(id, severity, resourceID string) models.Finding {
	return models.Finding{
		ID:         id,
		Severity:   severity,
		ResourceID: resourceID,
		Scope:      models.ScopeResource,
	}
}

func emptySnap() *models.AzureSnapshot {
	return &models.AzureSnapshot{
		SubscriptionID:   "00000000-0000-0000-0000-000000000001",
		SubscriptionName: "test-sub",
		TenantID:         "00000000-0000-0000-0000-0000000000ff",
		ScanTime:         time.Now(),
		DefenderPlans:    map[string]string{},
	}
}

// chainIDs returns just the chain identifiers from a correlator result for
// easy membership assertions.
func chainIDs(chains []models.AttackChain) map[string]bool {
	out := map[string]bool{}
	for _, c := range chains {
		out[c.ID] = true
	}
	return out
}

// ---------------------------------------------------------------------------
// ANCHOR_PLUS_ONE — CHAIN-001
// ---------------------------------------------------------------------------

func TestChain001_AnchorPlusOne_Fires(t *testing.T) {
	// anchor = zt_net_001, one other trigger fires (zt_wl_001).
	findings := []models.Finding{
		finding("zt_net_001", "CRITICAL", "/nsg/web"),
		finding("zt_wl_001", "HIGH", "/vm/web"),
	}

	chains := NewCorrelator().Correlate(findings, emptySnap())
	if !chainIDs(chains)["CHAIN-001"] {
		t.Fatalf("CHAIN-001 should fire when anchor zt_net_001 + one other trigger fires. got: %v", chainIDs(chains))
	}
}

func TestChain001_AnchorOnly_DoesNotFire(t *testing.T) {
	// anchor fires alone — ANCHOR_PLUS_ONE requires at least one other trigger.
	findings := []models.Finding{
		finding("zt_net_001", "CRITICAL", "/nsg/web"),
	}

	chains := NewCorrelator().Correlate(findings, emptySnap())
	if chainIDs(chains)["CHAIN-001"] {
		t.Fatalf("CHAIN-001 should NOT fire when only the anchor is present")
	}
}

func TestChain001_NoAnchor_DoesNotFire(t *testing.T) {
	// Other triggers fire but anchor is absent — chain must stay silent.
	findings := []models.Finding{
		finding("zt_wl_001", "HIGH", "/vm/web"),
		finding("zt_id_001", "HIGH", "/sp/backdoor"),
	}

	chains := NewCorrelator().Correlate(findings, emptySnap())
	if chainIDs(chains)["CHAIN-001"] {
		t.Fatalf("CHAIN-001 should NOT fire without its anchor zt_net_001")
	}
}

// ---------------------------------------------------------------------------
// ALL — CHAIN-002
// ---------------------------------------------------------------------------

func TestChain002_AllTriggers_Fires(t *testing.T) {
	// ALL => every trigger rule must have a finding.
	findings := []models.Finding{
		finding("zt_id_011", "CRITICAL", "/app/takeover"),
		finding("zt_net_009", "HIGH", "/nsg/mgmt"),
		finding("zt_wl_011", "HIGH", "/vm/compromised"),
	}

	chains := NewCorrelator().Correlate(findings, emptySnap())
	if !chainIDs(chains)["CHAIN-002"] {
		t.Fatalf("CHAIN-002 (ALL) should fire when every trigger is present")
	}
}

func TestChain002_PartialTriggers_DoesNotFire(t *testing.T) {
	// 2 of 3 triggers — ALL semantics means the chain must NOT fire.
	findings := []models.Finding{
		finding("zt_id_011", "CRITICAL", "/app/takeover"),
		finding("zt_net_009", "HIGH", "/nsg/mgmt"),
	}

	chains := NewCorrelator().Correlate(findings, emptySnap())
	if chainIDs(chains)["CHAIN-002"] {
		t.Fatalf("CHAIN-002 should NOT fire when one of the three ALL triggers is missing")
	}
}

// ---------------------------------------------------------------------------
// Participation index — MarkChainParticipants
// ---------------------------------------------------------------------------

func TestMarkChainParticipants_PopulatesParticipationIndex(t *testing.T) {
	findings := []models.Finding{
		finding("zt_net_001", "CRITICAL", "/nsg/web"),
		finding("zt_wl_001", "HIGH", "/vm/web"),
		finding("zt_data_001", "CRITICAL", "/sa/public"), // does not participate in CHAIN-001
	}

	c := NewCorrelator()
	chains := c.Correlate(findings, emptySnap())
	c.MarkChainParticipants(findings, chains)

	// zt_net_001 is an anchor for CHAIN-001 — ParticipatesInChains must
	// name the chain, and ChainPriority must be true.
	var net001, data001 *models.Finding
	for i := range findings {
		switch findings[i].ID {
		case "zt_net_001":
			net001 = &findings[i]
		case "zt_data_001":
			data001 = &findings[i]
		}
	}

	if net001 == nil {
		t.Fatal("zt_net_001 finding missing from input slice")
	}
	if !net001.ChainPriority {
		t.Errorf("zt_net_001 should have ChainPriority=true after participating in CHAIN-001")
	}
	found := false
	for _, id := range net001.ParticipatesInChains {
		if id == "CHAIN-001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("zt_net_001 should reference CHAIN-001 in ParticipatesInChains, got %v", net001.ParticipatesInChains)
	}

	// zt_data_001 does not participate in CHAIN-001 — ChainPriority stays
	// false unless some other emitted chain names it.
	if data001 != nil && data001.ChainPriority {
		for _, id := range data001.ParticipatesInChains {
			if id == "CHAIN-001" {
				t.Errorf("zt_data_001 incorrectly tagged as participant in CHAIN-001")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Severity sort — critical chains come first
// ---------------------------------------------------------------------------

func TestCorrelator_SortsBySeverity(t *testing.T) {
	// Emit two chains with different severities. CHAIN-001 is CRITICAL,
	// and CHAIN-008 (an ANCHOR_PLUS_ONE on zt_vis_003) is typically HIGH
	// in the builder. We just assert monotonic non-increasing severity
	// rank in the output order — a reversal would be a regression.
	findings := []models.Finding{
		finding("zt_net_001", "CRITICAL", "/nsg/web"),
		finding("zt_wl_001", "HIGH", "/vm/web"),
		finding("zt_vis_003", "HIGH", "VirtualMachines"),
		finding("zt_net_002", "HIGH", "/nsg/mgmt"),
	}

	chains := NewCorrelator().Correlate(findings, emptySnap())
	if len(chains) < 2 {
		t.Skipf("need at least 2 chains to check sort order, got %d", len(chains))
	}
	for i := 1; i < len(chains); i++ {
		prev := severityRank(chains[i-1].Severity)
		cur := severityRank(chains[i].Severity)
		if prev > cur {
			t.Errorf("chain %s (%s) came before %s (%s) — severities out of order",
				chains[i-1].ID, chains[i-1].Severity, chains[i].ID, chains[i].Severity)
		}
	}
}
