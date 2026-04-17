package engine

import (
	"strings"
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

// mkFinding returns a Finding populated with just enough data for the
// correlator to consider it a trigger match.
func mkFinding(id, severity, pillar, resourceID, resourceName string) models.Finding {
	return models.Finding{
		ID:           id,
		Severity:     severity,
		Pillar:       pillar,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Source:       "argus-zt",
	}
}

// findChain returns a pointer to the first chain with the given ID in the
// slice, or nil if not present.
func findChain(chains []models.AttackChain, id string) *models.AttackChain {
	for i := range chains {
		if chains[i].ID == id {
			return &chains[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// CHAIN-001 — Internet-exposed VM to subscription takeover
// ---------------------------------------------------------------------------

func TestChain001_InternetExposedVMToSubscriptionTakeover(t *testing.T) {
	findings := []models.Finding{
		mkFinding("zt_net_001", "CRITICAL", "Network", "/sub/.../nsg/web-nsg", "web-nsg"),
		mkFinding("zt_wl_001", "HIGH", "Workload", "/sub/.../vm/web-01", "web-01"),
		mkFinding("zt_id_001", "HIGH", "Identity", "/sub/.../sp/svc-deploy", "svc-deploy"),
	}
	correlator := NewCorrelator()
	chains := correlator.Correlate(findings, &models.AzureSnapshot{})

	chain001 := findChain(chains, "CHAIN-001")
	if chain001 == nil {
		t.Fatal("CHAIN-001 should have been detected")
	}
	if chain001.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %s", chain001.Severity)
	}

	found := false
	for _, fix := range chain001.MinimalFixSet {
		if fix == "zt_net_001" {
			found = true
		}
	}
	if !found {
		t.Error("MinimalFixSet should contain zt_net_001")
	}
}

func TestChain001_NotTriggered_MissingAnchor(t *testing.T) {
	findings := []models.Finding{
		mkFinding("zt_wl_001", "HIGH", "Workload", "/sub/.../vm/web-01", "web-01"),
		mkFinding("zt_id_001", "HIGH", "Identity", "/sub/.../sp/svc-deploy", "svc-deploy"),
	}
	correlator := NewCorrelator()
	chains := correlator.Correlate(findings, &models.AzureSnapshot{})
	if findChain(chains, "CHAIN-001") != nil {
		t.Fatal("CHAIN-001 should NOT have been detected without anchor")
	}
}

// ---------------------------------------------------------------------------
// CHAIN-002 — App Registration Graph abuse to tenant data
// ---------------------------------------------------------------------------

func TestChain002_AppRegistrationGraphAbuse(t *testing.T) {
	findings := []models.Finding{
		mkFinding("zt_id_011", "CRITICAL", "Identity", "/sub/.../app/example", "example-app"),
		mkFinding("zt_net_009", "HIGH", "Network", "/sub/.../sa/proddata", "proddata"),
		mkFinding("zt_wl_011", "HIGH", "Workload", "/sub/.../app/legacy", "legacy-app"),
	}
	correlator := NewCorrelator()
	chains := correlator.Correlate(findings, &models.AzureSnapshot{})

	chain := findChain(chains, "CHAIN-002")
	if chain == nil {
		t.Fatal("CHAIN-002 (App Registration takeover) should have been detected")
	}
	if !strings.Contains(chain.Title, "App Registration") {
		t.Errorf("CHAIN-002 title should mention App Registration: %s", chain.Title)
	}
	if len(chain.Steps) < 5 {
		t.Errorf("CHAIN-002 should have at least 5 steps, got %d", len(chain.Steps))
	}

	hasGDPR := false
	for _, r := range chain.RegulatoryImpact {
		if strings.Contains(strings.ToUpper(r.Framework), "GDPR") {
			hasGDPR = true
			break
		}
	}
	if !hasGDPR {
		t.Error("CHAIN-002 RegulatoryImpact should include GDPR")
	}
}

func TestChain002_NotTriggered_MissingOne(t *testing.T) {
	// Missing zt_wl_011 - ALL logic means no trigger.
	findings := []models.Finding{
		mkFinding("zt_id_011", "CRITICAL", "Identity", "/sub/.../app/example", "example-app"),
		mkFinding("zt_net_009", "HIGH", "Network", "/sub/.../sa/proddata", "proddata"),
	}
	correlator := NewCorrelator()
	chains := correlator.Correlate(findings, &models.AzureSnapshot{})
	if findChain(chains, "CHAIN-002") != nil {
		t.Fatal("CHAIN-002 should NOT fire when a trigger is missing")
	}
}

// ---------------------------------------------------------------------------
// Table-driven happy-path and miss tests for every chain
// ---------------------------------------------------------------------------

// chainTriggerCase describes one chain's minimum positive trigger set (the
// set of rule IDs that causes the chain to match) and a "miss" rule ID to
// remove when building the negative case.
type chainTriggerCase struct {
	name    string
	chainID string
	// triggers is the full set of rule IDs for the happy-path trigger. For
	// ALL-logic chains this must cover every required rule. For
	// ANCHOR_PLUS_ONE chains it must contain the anchor plus at least one
	// auxiliary rule.
	triggers []string
	// anchor, if set, is the rule that must be present for
	// ANCHOR_PLUS_ONE chains. When present the negative test drops the
	// anchor; otherwise the first trigger is dropped.
	anchor string
}

func triggerCases() []chainTriggerCase {
	return []chainTriggerCase{
		{"chain001", "CHAIN-001", []string{"zt_net_001", "zt_wl_001"}, "zt_net_001"},
		{"chain002", "CHAIN-002", []string{"zt_id_011", "zt_net_009", "zt_wl_011"}, ""},
		{"chain003", "CHAIN-003", []string{"zt_id_005", "zt_id_006", "zt_id_003"}, ""},
		{"chain004", "CHAIN-004", []string{"zt_id_003", "zt_id_007", "zt_vis_008"}, ""},
		{"chain005", "CHAIN-005", []string{"zt_data_001", "zt_vis_001", "zt_data_006"}, ""},
		{"chain006", "CHAIN-006", []string{"zt_wl_003", "zt_wl_007", "zt_data_004"}, ""},
		{"chain007", "CHAIN-007", []string{"zt_net_003", "zt_vis_006", "zt_vis_009"}, ""},
		{"chain008", "CHAIN-008", []string{"zt_vis_003", "zt_net_001"}, "zt_vis_003"},
		{"chain009", "CHAIN-009", []string{"zt_data_004", "zt_data_005", "zt_vis_004"}, ""},
		{"chain010", "CHAIN-010", []string{"zt_net_010", "zt_data_007", "zt_data_003"}, ""},
		{"chain011", "CHAIN-011", []string{"zt_id_004", "zt_id_006", "zt_vis_005"}, ""},
		{"chain012", "CHAIN-012", []string{"zt_wl_004", "zt_wl_010", "zt_vis_001"}, ""},
		{"chain013", "CHAIN-013", []string{"zt_net_004", "zt_net_005", "zt_vis_006"}, ""},
		{"chain014", "CHAIN-014", []string{"zt_data_008", "zt_data_001", "zt_net_009"}, ""},
		{"chain015", "CHAIN-015", []string{"zt_wl_005", "zt_wl_008", "zt_data_009"}, ""},
		{"chain016", "CHAIN-016", []string{"zt_vis_010", "zt_net_001", "zt_vis_008"}, ""},
		{"chain017", "CHAIN-017", []string{"zt_id_009", "zt_id_010", "zt_vis_004"}, ""},
		{"chain018", "CHAIN-018", []string{"zt_net_008", "zt_net_007", "zt_wl_006"}, ""},
		{"chain019", "CHAIN-019", []string{"zt_id_003", "zt_id_007", "zt_id_010"}, ""},
		{"chain020", "CHAIN-020", []string{"zt_vis_007", "zt_vis_001", "zt_vis_005"}, ""},
		{"chain021", "CHAIN-021", []string{"zt_wl_002", "zt_wl_003", "zt_wl_007"}, ""},
		// v1.1 new chains (022-051)
		{"chain022", "CHAIN-022", []string{"zt_id_012", "zt_id_014", "zt_id_021"}, ""},
		{"chain023", "CHAIN-023", []string{"zt_id_013", "zt_id_018", "zt_id_023"}, ""},
		{"chain024", "CHAIN-024", []string{"zt_id_017", "zt_id_016", "zt_data_011"}, ""},
		{"chain025", "CHAIN-025", []string{"zt_wl_014", "zt_wl_015", "zt_wl_016"}, ""},
		{"chain026", "CHAIN-026", []string{"zt_wl_012", "zt_wl_013", "zt_wl_021"}, ""},
		{"chain027", "CHAIN-027", []string{"zt_wl_018", "zt_net_019", "zt_vis_019"}, ""},
		{"chain028", "CHAIN-028", []string{"zt_data_014", "zt_vis_014", "zt_id_024"}, ""},
		{"chain029", "CHAIN-029", []string{"zt_data_012", "zt_vis_015", "zt_data_015"}, ""},
		{"chain030", "CHAIN-030", []string{"zt_data_013", "zt_data_016", "zt_data_017"}, ""},
		{"chain031", "CHAIN-031", []string{"zt_net_011", "zt_net_019", "zt_net_018"}, ""},
		{"chain032", "CHAIN-032", []string{"zt_net_014", "zt_wl_017", "zt_vis_019"}, ""},
		{"chain033", "CHAIN-033", []string{"zt_id_021", "zt_vis_017", "zt_id_019"}, ""},
		{"chain034", "CHAIN-034", []string{"zt_id_016", "zt_id_017", "zt_id_013"}, ""},
		{"chain035", "CHAIN-035", []string{"zt_data_020", "zt_net_011", "zt_vis_011"}, ""},
		{"chain036", "CHAIN-036", []string{"zt_data_019", "zt_data_018", "zt_vis_016"}, ""},
		{"chain037", "CHAIN-037", []string{"zt_net_015", "zt_net_016", "zt_net_020"}, ""},
		{"chain038", "CHAIN-038", []string{"zt_net_017", "zt_net_013", "zt_wl_019"}, ""},
		{"chain039", "CHAIN-039", []string{"zt_wl_022", "zt_wl_014", "zt_data_014"}, ""},
		{"chain040", "CHAIN-040", []string{"zt_id_018", "zt_id_022", "zt_id_015"}, ""},
		{"chain041", "CHAIN-041", []string{"zt_vis_011", "zt_vis_017", "zt_vis_018"}, ""},
		{"chain042", "CHAIN-042", []string{"zt_wl_020", "zt_data_017", "zt_vis_012"}, ""},
		{"chain043", "CHAIN-043", []string{"zt_net_012", "zt_net_018", "zt_vis_013"}, ""},
		{"chain044", "CHAIN-044", []string{"zt_id_014", "zt_id_023", "zt_id_012"}, ""},
		{"chain045", "CHAIN-045", []string{"zt_data_018", "zt_data_019", "zt_net_011"}, ""},
		{"chain046", "CHAIN-046", []string{"zt_wl_017", "zt_id_025", "zt_net_019"}, ""},
		{"chain047", "CHAIN-047", []string{"zt_vis_013", "zt_net_019", "zt_vis_016"}, ""},
		{"chain048", "CHAIN-048", []string{"zt_data_011", "zt_vis_014", "zt_data_014"}, ""},
		{"chain049", "CHAIN-049", []string{"zt_wl_013", "zt_wl_012"}, "zt_wl_013"},
		{"chain050", "CHAIN-050", []string{"zt_vis_020", "zt_vis_012", "zt_vis_018"}, ""},
		{"chain051", "CHAIN-051", []string{"zt_id_019", "zt_id_014", "zt_vis_017"}, ""},
	}
}

func findingsFromRules(ruleIDs []string) []models.Finding {
	out := make([]models.Finding, 0, len(ruleIDs))
	for i, id := range ruleIDs {
		pillar := "Identity"
		if strings.HasPrefix(id, "zt_net") {
			pillar = "Network"
		} else if strings.HasPrefix(id, "zt_wl") {
			pillar = "Workload"
		} else if strings.HasPrefix(id, "zt_data") {
			pillar = "Data"
		} else if strings.HasPrefix(id, "zt_vis") {
			pillar = "Visibility"
		}
		out = append(out, mkFinding(
			id,
			"HIGH",
			pillar,
			"/sub/test/rid/"+id,
			"res-"+id+"-"+itoa(i),
		))
	}
	return out
}

// itoa is a tiny helper so this file does not need to import strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := "0123456789"
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := []byte{}
	for n > 0 {
		buf = append([]byte{digits[n%10]}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

func TestAllChainsTriggered(t *testing.T) {
	for _, tc := range triggerCases() {
		tc := tc
		t.Run(tc.name+"_positive", func(t *testing.T) {
			findings := findingsFromRules(tc.triggers)
			correlator := NewCorrelator()
			chains := correlator.Correlate(findings, &models.AzureSnapshot{})
			chain := findChain(chains, tc.chainID)
			if chain == nil {
				t.Fatalf("%s should be detected with triggers %v", tc.chainID, tc.triggers)
			}
			if chain.ID != tc.chainID {
				t.Errorf("expected chain ID %s, got %s", tc.chainID, chain.ID)
			}
			if chain.Title == "" {
				t.Error("chain should have a non-empty title")
			}
			if len(chain.Steps) == 0 {
				t.Error("chain should have at least one narrative step")
			}
			if len(chain.TriggerFindings) == 0 {
				t.Error("chain should report its trigger findings")
			}
			if len(chain.MinimalFixSet) == 0 {
				t.Error("chain should propose a minimal fix set")
			}
			if len(chain.RegulatoryImpact) == 0 {
				t.Error("chain should include at least one regulatory impact entry")
			}
		})
	}
}

func TestAllChainsNotTriggered_MissingTrigger(t *testing.T) {
	for _, tc := range triggerCases() {
		tc := tc
		t.Run(tc.name+"_negative", func(t *testing.T) {
			// Drop either the anchor or the first trigger.
			drop := tc.anchor
			if drop == "" {
				drop = tc.triggers[0]
			}
			remaining := make([]string, 0, len(tc.triggers))
			for _, id := range tc.triggers {
				if id == drop {
					continue
				}
				remaining = append(remaining, id)
			}
			findings := findingsFromRules(remaining)
			correlator := NewCorrelator()
			chains := correlator.Correlate(findings, &models.AzureSnapshot{})
			if findChain(chains, tc.chainID) != nil {
				t.Fatalf("%s should NOT be detected after dropping %q (remaining=%v)", tc.chainID, drop, remaining)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-cutting correlator tests
// ---------------------------------------------------------------------------

func TestCorrelator_ChainPrioritySetOnFindings(t *testing.T) {
	findings := []models.Finding{
		mkFinding("zt_net_001", "CRITICAL", "Network", "id1", "nsg1"),
		mkFinding("zt_wl_001", "HIGH", "Workload", "id2", "vm1"),
		mkFinding("zt_id_001", "HIGH", "Identity", "id3", "sp1"),
		mkFinding("cis_3_3", "HIGH", "Data", "id4", "storage1"), // not in any chain
	}
	correlator := NewCorrelator()
	chains := correlator.Correlate(findings, &models.AzureSnapshot{})
	correlator.MarkChainParticipants(findings, chains)

	for i, f := range findings {
		switch f.ID {
		case "zt_net_001", "zt_wl_001", "zt_id_001":
			if !findings[i].ChainPriority {
				t.Errorf("%s should have ChainPriority=true", f.ID)
			}
		case "cis_3_3":
			if findings[i].ChainPriority {
				t.Error("cis_3_3 should NOT have ChainPriority=true")
			}
		}
	}
}

func TestCorrelator_ParticipatesInChainsPopulated(t *testing.T) {
	// zt_id_003 is in both CHAIN-004 and CHAIN-019.
	findings := []models.Finding{
		mkFinding("zt_id_003", "HIGH", "Identity", "id1", "rbac"),
		mkFinding("zt_id_007", "MEDIUM", "Identity", "id2", "tenant"),
		mkFinding("zt_vis_008", "MEDIUM", "Visibility", "id3", "alerts"),
		mkFinding("zt_id_010", "MEDIUM", "Identity", "id4", "reviews"),
	}
	correlator := NewCorrelator()
	chains := correlator.Correlate(findings, &models.AzureSnapshot{})
	correlator.MarkChainParticipants(findings, chains)

	idx := -1
	for i, f := range findings {
		if f.ID == "zt_id_003" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("zt_id_003 not found")
	}
	if len(findings[idx].ParticipatesInChains) < 2 {
		t.Errorf("zt_id_003 should participate in >=2 chains, got %d (%v)",
			len(findings[idx].ParticipatesInChains), findings[idx].ParticipatesInChains)
	}
}

func TestCorrelator_SortingCriticalFirst(t *testing.T) {
	findings := []models.Finding{
		// CHAIN-004 is HIGH severity.
		mkFinding("zt_id_003", "HIGH", "Identity", "id1", "rbac"),
		mkFinding("zt_id_007", "HIGH", "Identity", "id2", "tenant"),
		mkFinding("zt_vis_008", "HIGH", "Visibility", "id3", "alerts"),
		// CHAIN-003 is CRITICAL severity.
		mkFinding("zt_id_005", "CRITICAL", "Identity", "id4", "legacy-auth"),
		mkFinding("zt_id_006", "CRITICAL", "Identity", "id5", "cap"),
	}
	correlator := NewCorrelator()
	chains := correlator.Correlate(findings, &models.AzureSnapshot{})

	if len(chains) < 2 {
		t.Fatalf("expected at least 2 chains, got %d", len(chains))
	}
	// The first chain in the sorted output must be CRITICAL.
	if chains[0].Severity != "CRITICAL" {
		t.Errorf("expected first chain to be CRITICAL severity, got %s (%s)", chains[0].Severity, chains[0].ID)
	}
}

func TestCorrelator_EmptyFindingsProduceNoChains(t *testing.T) {
	correlator := NewCorrelator()
	chains := correlator.Correlate(nil, &models.AzureSnapshot{})
	if len(chains) != 0 {
		t.Errorf("expected no chains with empty findings, got %d", len(chains))
	}
}
