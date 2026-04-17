package graph

import (
	"strings"
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sampleFindings() []models.Finding {
	return []models.Finding{
		{
			ID:             "cis_1_1",
			Title:          "MFA not enabled for admins",
			Severity:       "CRITICAL",
			Pillar:         "Identity",
			ResourceID:     "/subscriptions/sub1/users/admin1",
			ResourceName:   "admin1",
			ResourceType:   "Microsoft.Graph/users",
			MITRETechnique: "T1078",
		},
		{
			ID:             "cis_3_1",
			Title:          "Storage account allows public access",
			Severity:       "HIGH",
			Pillar:         "Data",
			ResourceID:     "/subscriptions/sub1/storageAccounts/sa1",
			ResourceName:   "sa1",
			ResourceType:   "Microsoft.Storage/storageAccounts",
			MITRETechnique: "T1530",
		},
		{
			ID:             "cis_5_1",
			Title:          "NSG allows unrestricted SSH",
			Severity:       "CRITICAL",
			Pillar:         "Network",
			ResourceID:     "/subscriptions/sub1/nsgs/nsg1",
			ResourceName:   "nsg1",
			ResourceType:   "Microsoft.Network/networkSecurityGroups",
			MITRETechnique: "T1190",
		},
	}
}

func sampleChains() []models.AttackChain {
	return []models.AttackChain{
		{
			ID:              "CHAIN-001",
			Title:           "Credential Theft to Data Exfil",
			Severity:        "CRITICAL",
			Likelihood:      "HIGH",
			TriggerFindings: []string{"cis_1_1", "cis_3_1"},
			Steps: []models.ChainStep{
				{Number: 1, EnabledBy: "cis_1_1", Technique: "T1078", Action: "Authenticate as admin"},
				{Number: 2, EnabledBy: "cis_3_1", Technique: "T1530", Action: "Access storage"},
			},
			AffectedResources: []string{
				"/subscriptions/sub1/users/admin1",
				"/subscriptions/sub1/storageAccounts/sa1",
			},
			MITRETechnique: "T1078",
			PriorityFix:    "Enable MFA",
		},
		{
			ID:              "CHAIN-002",
			Title:           "Network Pivot via SSH",
			Severity:        "HIGH",
			Likelihood:      "MEDIUM",
			TriggerFindings: []string{"cis_5_1"},
			Steps: []models.ChainStep{
				{Number: 1, EnabledBy: "cis_5_1", Technique: "T1190", Action: "Exploit SSH"},
			},
			AffectedResources: []string{
				"/subscriptions/sub1/nsgs/nsg1",
			},
			MITRETechnique: "T1190",
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestBuildGraph_Basic(t *testing.T) {
	g := BuildGraph(sampleChains(), sampleFindings())

	if g == nil {
		t.Fatal("BuildGraph returned nil")
	}
	if len(g.Nodes) == 0 {
		t.Fatal("expected nodes, got 0")
	}
	if len(g.Edges) == 0 {
		t.Fatal("expected edges, got 0")
	}

	// We should have: 3 findings + 2 chains + 3 resources + 3 techniques = 11 nodes.
	// (T1078, T1530, T1190 are the unique techniques.)
	if g.Stats.FindingNodes != 3 {
		t.Errorf("expected 3 finding nodes, got %d", g.Stats.FindingNodes)
	}
	if g.Stats.ChainNodes != 2 {
		t.Errorf("expected 2 chain nodes, got %d", g.Stats.ChainNodes)
	}
	if g.Stats.ResourceNodes != 3 {
		t.Errorf("expected 3 resource nodes, got %d", g.Stats.ResourceNodes)
	}
	if g.Stats.TechniqueNodes != 3 {
		t.Errorf("expected 3 technique nodes, got %d", g.Stats.TechniqueNodes)
	}
}

func TestBuildGraph_NodeDeduplication(t *testing.T) {
	findings := sampleFindings()
	chains := sampleChains()

	g := BuildGraph(chains, findings)

	// Count how many times each node ID appears.
	seen := make(map[string]int)
	for _, n := range g.Nodes {
		seen[n.ID]++
	}

	for id, count := range seen {
		if count > 1 {
			t.Errorf("node %q appears %d times (should be 1)", id, count)
		}
	}

	// Resource /subscriptions/sub1/users/admin1 is in both findings and
	// chain.AffectedResources — should be deduplicated.
	resID := "resource:/subscriptions/sub1/users/admin1"
	if seen[resID] != 1 {
		t.Errorf("expected resource node %q exactly once, got %d", resID, seen[resID])
	}
}

func TestBuildGraph_EdgeTypes(t *testing.T) {
	g := BuildGraph(sampleChains(), sampleFindings())

	edgeTypes := make(map[string]int)
	for _, e := range g.Edges {
		edgeTypes[e.Type]++
	}

	if edgeTypes["triggers"] == 0 {
		t.Error("expected at least one 'triggers' edge")
	}
	if edgeTypes["affects"] == 0 {
		t.Error("expected at least one 'affects' edge")
	}
	if edgeTypes["uses_technique"] == 0 {
		t.Error("expected at least one 'uses_technique' edge")
	}
	if edgeTypes["enables"] == 0 {
		t.Error("expected at least one 'enables' edge")
	}
}

func TestBuildGraph_EnablesEdges(t *testing.T) {
	g := BuildGraph(sampleChains(), sampleFindings())

	// CHAIN-001 has steps cis_1_1 → cis_3_1, so we expect an "enables" edge.
	found := false
	for _, e := range g.Edges {
		if e.Type == "enables" && e.Source == "finding:cis_1_1" && e.Target == "finding:cis_3_1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected enables edge from finding:cis_1_1 → finding:cis_3_1")
	}
}

func TestBuildGraph_Stats(t *testing.T) {
	g := BuildGraph(sampleChains(), sampleFindings())

	if g.Stats.TotalNodes != len(g.Nodes) {
		t.Errorf("TotalNodes mismatch: stats=%d actual=%d", g.Stats.TotalNodes, len(g.Nodes))
	}
	if g.Stats.TotalEdges != len(g.Edges) {
		t.Errorf("TotalEdges mismatch: stats=%d actual=%d", g.Stats.TotalEdges, len(g.Edges))
	}
	if g.Stats.MostConnectedNode == "" {
		t.Error("MostConnectedNode should not be empty")
	}
	if g.Stats.PillarDistribution["Identity"] != 1 {
		t.Errorf("expected Identity pillar count 1, got %d", g.Stats.PillarDistribution["Identity"])
	}
	if g.Stats.PillarDistribution["Data"] != 1 {
		t.Errorf("expected Data pillar count 1, got %d", g.Stats.PillarDistribution["Data"])
	}
	if g.Stats.PillarDistribution["Network"] != 1 {
		t.Errorf("expected Network pillar count 1, got %d", g.Stats.PillarDistribution["Network"])
	}
}

func TestBuildGraph_CriticalPaths(t *testing.T) {
	// CHAIN-002 triggers: [cis_5_1] which is CRITICAL → 1 critical path.
	// CHAIN-001 triggers: [cis_1_1 (CRITICAL), cis_3_1 (HIGH)] → not all critical.
	g := BuildGraph(sampleChains(), sampleFindings())

	if g.Stats.CriticalPaths != 1 {
		t.Errorf("expected 1 critical path, got %d", g.Stats.CriticalPaths)
	}
}

func TestBuildGraph_EmptyInputs(t *testing.T) {
	g := BuildGraph(nil, nil)
	if g == nil {
		t.Fatal("BuildGraph returned nil for empty inputs")
	}
	if len(g.Nodes) != 0 {
		t.Errorf("expected 0 nodes for empty input, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected 0 edges for empty input, got %d", len(g.Edges))
	}
	if g.Stats.TotalNodes != 0 {
		t.Errorf("expected 0 total nodes, got %d", g.Stats.TotalNodes)
	}
	if g.Stats.CriticalPaths != 0 {
		t.Errorf("expected 0 critical paths, got %d", g.Stats.CriticalPaths)
	}
}

func TestBuildGraph_FindingsOnly(t *testing.T) {
	g := BuildGraph(nil, sampleFindings())
	if g.Stats.FindingNodes != 3 {
		t.Errorf("expected 3 finding nodes, got %d", g.Stats.FindingNodes)
	}
	if g.Stats.ChainNodes != 0 {
		t.Errorf("expected 0 chain nodes, got %d", g.Stats.ChainNodes)
	}
	// Each finding has a technique → 3 uses_technique edges.
	techEdges := 0
	for _, e := range g.Edges {
		if e.Type == "uses_technique" {
			techEdges++
		}
	}
	if techEdges != 3 {
		t.Errorf("expected 3 uses_technique edges, got %d", techEdges)
	}
}

func TestExportDOT_Format(t *testing.T) {
	g := BuildGraph(sampleChains(), sampleFindings())
	dot := ExportDOT(g)

	if !strings.HasPrefix(dot, "digraph AttackGraph {") {
		t.Error("DOT output should start with 'digraph AttackGraph {'")
	}
	if !strings.HasSuffix(strings.TrimSpace(dot), "}") {
		t.Error("DOT output should end with '}'")
	}
	if !strings.Contains(dot, "rankdir=LR") {
		t.Error("DOT output should contain rankdir=LR")
	}
	// Check that nodes and edges are present.
	if !strings.Contains(dot, "chain:CHAIN-001") {
		t.Error("DOT should contain chain:CHAIN-001 node")
	}
	if !strings.Contains(dot, "->") {
		t.Error("DOT should contain edges (->)")
	}
	// Check shape assignments.
	if !strings.Contains(dot, "shape=hexagon") {
		t.Error("DOT should use hexagon shape for chain nodes")
	}
	if !strings.Contains(dot, "shape=ellipse") {
		t.Error("DOT should use ellipse shape for finding nodes")
	}
	if !strings.Contains(dot, "shape=diamond") {
		t.Error("DOT should use diamond shape for technique nodes")
	}
}

func TestExportDOT_Empty(t *testing.T) {
	g := BuildGraph(nil, nil)
	dot := ExportDOT(g)
	if !strings.HasPrefix(dot, "digraph AttackGraph {") {
		t.Error("empty graph DOT should still be valid")
	}
	// Should have no node or edge lines (only boilerplate).
	lines := strings.Split(dot, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "->") {
			t.Error("empty graph should have no edges")
		}
	}
}
