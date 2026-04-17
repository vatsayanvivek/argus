// Package graph builds a directed attack-surface graph from ARGUS findings
// and attack chains.  The resulting AttackGraph is designed for serialisation
// to JSON (for D3.js / Cytoscape.js frontends) or DOT (for Graphviz).
package graph

import (
	"fmt"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// AttackGraph is the full attack-surface graph produced by BuildGraph.
type AttackGraph struct {
	Nodes []Node     `json:"nodes"`
	Edges []Edge     `json:"edges"`
	Stats GraphStats `json:"stats"`
}

// Node is a single vertex in the graph.
type Node struct {
	ID       string            `json:"id"`
	Label    string            `json:"label"`
	Type     string            `json:"type"` // "finding", "chain", "resource", "technique"
	Severity string            `json:"severity,omitempty"`
	Pillar   string            `json:"pillar,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
	Type   string `json:"type"` // "triggers", "enables", "affects", "uses_technique"
	Weight int    `json:"weight,omitempty"`
}

// GraphStats holds summary statistics for the graph.
type GraphStats struct {
	TotalNodes         int            `json:"total_nodes"`
	TotalEdges         int            `json:"total_edges"`
	FindingNodes       int            `json:"finding_nodes"`
	ChainNodes         int            `json:"chain_nodes"`
	ResourceNodes      int            `json:"resource_nodes"`
	TechniqueNodes     int            `json:"technique_nodes"`
	MostConnectedNode  string         `json:"most_connected_node"`
	CriticalPaths      int            `json:"critical_paths"`
	PillarDistribution map[string]int `json:"pillar_distribution"`
}

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

// BuildGraph creates an AttackGraph from a set of attack chains and findings.
//
// Node creation rules:
//   - One "chain" node per AttackChain (keyed by chain.ID).
//   - One "finding" node per unique Finding.ID (rule_id).
//   - One "resource" node per unique resource ID appearing in
//     chain.AffectedResources or finding.ResourceID.
//   - One "technique" node per unique MITRE technique ID appearing in
//     chain.MITRETechnique, chain step.Technique, or finding.MITRETechnique.
//
// Edge creation rules:
//   - finding → chain   (type "triggers")  for each chain.TriggerFindings entry.
//   - chain  → resource (type "affects")   for each chain.AffectedResources entry.
//   - finding → technique (type "uses_technique") when finding.MITRETechnique != "".
//   - finding → finding (type "enables") for sequential chain steps where
//     step[N].EnabledBy → step[N+1].EnabledBy.
func BuildGraph(chains []models.AttackChain, findings []models.Finding) *AttackGraph {
	g := &AttackGraph{
		Stats: GraphStats{
			PillarDistribution: make(map[string]int),
		},
	}

	// Indexes for deduplication.
	nodeIndex := make(map[string]bool)   // id → exists
	edgeIndex := make(map[string]bool)   // "source|target|type" → exists
	findingByID := make(map[string]models.Finding)

	for _, f := range findings {
		findingByID[f.ID] = f
	}

	// Helper: add node if not seen.
	addNode := func(n Node) {
		if nodeIndex[n.ID] {
			return
		}
		nodeIndex[n.ID] = true
		g.Nodes = append(g.Nodes, n)
	}

	// Helper: add edge if not seen.
	addEdge := func(e Edge) {
		key := e.Source + "|" + e.Target + "|" + e.Type
		if edgeIndex[key] {
			return
		}
		edgeIndex[key] = true
		g.Edges = append(g.Edges, e)
	}

	// Helper: add technique node + edge from a source node.
	addTechnique := func(sourceID, technique string) {
		if technique == "" {
			return
		}
		techID := "technique:" + technique
		addNode(Node{
			ID:    techID,
			Label: technique,
			Type:  "technique",
		})
		addEdge(Edge{
			Source: sourceID,
			Target: techID,
			Type:   "uses_technique",
			Label:  "uses",
		})
	}

	// 1. Create finding nodes from the findings slice.
	for _, f := range findings {
		fID := "finding:" + f.ID
		addNode(Node{
			ID:       fID,
			Label:    f.Title,
			Type:     "finding",
			Severity: f.Severity,
			Pillar:   f.Pillar,
			Metadata: map[string]string{
				"resource_id": f.ResourceID,
				"cis_rule":    f.CISRule,
			},
		})
		addTechnique(fID, f.MITRETechnique)

		// Resource node from finding.
		if f.ResourceID != "" {
			resID := "resource:" + f.ResourceID
			addNode(Node{
				ID:    resID,
				Label: f.ResourceName,
				Type:  "resource",
				Metadata: map[string]string{
					"resource_type": f.ResourceType,
					"location":      f.Location,
				},
			})
		}
	}

	// 2. Create chain nodes and their edges.
	for _, c := range chains {
		chainNodeID := "chain:" + c.ID
		addNode(Node{
			ID:       chainNodeID,
			Label:    c.Title,
			Type:     "chain",
			Severity: c.Severity,
			Metadata: map[string]string{
				"likelihood":  c.Likelihood,
				"priority_fix": c.PriorityFix,
			},
		})

		// Chain-level MITRE technique node.
		if c.MITRETechnique != "" {
			techID := "technique:" + c.MITRETechnique
			addNode(Node{
				ID:    techID,
				Label: c.MITRETechnique,
				Type:  "technique",
			})
		}

		// trigger finding → chain edges.
		for _, triggerRuleID := range c.TriggerFindings {
			fID := "finding:" + triggerRuleID
			// Ensure a node exists even if the finding was not in the
			// findings slice (defensive).
			if f, ok := findingByID[triggerRuleID]; ok {
				addNode(Node{
					ID:       fID,
					Label:    f.Title,
					Type:     "finding",
					Severity: f.Severity,
					Pillar:   f.Pillar,
				})
			} else {
				addNode(Node{
					ID:    fID,
					Label: triggerRuleID,
					Type:  "finding",
				})
			}
			addEdge(Edge{
				Source: fID,
				Target: chainNodeID,
				Type:   "triggers",
				Label:  "triggers",
			})
		}

		// chain → affected resource edges.
		for _, resID := range c.AffectedResources {
			nodeResID := "resource:" + resID
			addNode(Node{
				ID:    nodeResID,
				Label: resID,
				Type:  "resource",
			})
			addEdge(Edge{
				Source: chainNodeID,
				Target: nodeResID,
				Type:   "affects",
				Label:  "affects",
			})
		}

		// Step technique nodes.
		for _, step := range c.Steps {
			if step.Technique != "" {
				techID := "technique:" + step.Technique
				addNode(Node{
					ID:    techID,
					Label: step.Technique,
					Type:  "technique",
				})
			}
		}

		// Sequential chain-step "enables" edges (step N → step N+1).
		for i := 0; i < len(c.Steps)-1; i++ {
			fromRule := c.Steps[i].EnabledBy
			toRule := c.Steps[i+1].EnabledBy
			if fromRule == "" || toRule == "" || fromRule == toRule {
				continue
			}
			addEdge(Edge{
				Source: "finding:" + fromRule,
				Target: "finding:" + toRule,
				Type:   "enables",
				Label:  "enables",
			})
		}
	}

	// 3. Compute stats.
	g.computeStats()

	return g
}

// ---------------------------------------------------------------------------
// Stats computation
// ---------------------------------------------------------------------------

// computeStats populates g.Stats from the current nodes and edges.
func (g *AttackGraph) computeStats() {
	g.Stats.TotalNodes = len(g.Nodes)
	g.Stats.TotalEdges = len(g.Edges)
	g.Stats.PillarDistribution = make(map[string]int)

	for _, n := range g.Nodes {
		switch n.Type {
		case "finding":
			g.Stats.FindingNodes++
			if n.Pillar != "" {
				g.Stats.PillarDistribution[n.Pillar]++
			}
		case "chain":
			g.Stats.ChainNodes++
		case "resource":
			g.Stats.ResourceNodes++
		case "technique":
			g.Stats.TechniqueNodes++
		}
	}

	// Most connected node: highest degree (in + out).
	degree := make(map[string]int)
	for _, e := range g.Edges {
		degree[e.Source]++
		degree[e.Target]++
	}
	maxDeg := 0
	for id, d := range degree {
		if d > maxDeg {
			maxDeg = d
			g.Stats.MostConnectedNode = id
		}
	}

	// Critical paths: count chains where every trigger finding is CRITICAL.
	g.Stats.CriticalPaths = g.countCriticalPaths()
}

// countCriticalPaths counts the number of chain nodes for which every
// inbound "triggers" edge originates from a CRITICAL-severity finding node.
// A chain with zero trigger edges is not counted.
func (g *AttackGraph) countCriticalPaths() int {
	severityOf := make(map[string]string)
	for _, n := range g.Nodes {
		if n.Severity != "" {
			severityOf[n.ID] = n.Severity
		}
	}

	// Collect trigger sources per chain node.
	chainTriggers := make(map[string][]string) // chainNodeID → []findingNodeID
	for _, e := range g.Edges {
		if e.Type == "triggers" {
			chainTriggers[e.Target] = append(chainTriggers[e.Target], e.Source)
		}
	}

	count := 0
	for _, triggers := range chainTriggers {
		if len(triggers) == 0 {
			continue
		}
		allCritical := true
		for _, fID := range triggers {
			if severityOf[fID] != "CRITICAL" {
				allCritical = false
				break
			}
		}
		if allCritical {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// DOT export
// ---------------------------------------------------------------------------

// ExportDOT renders the graph in Graphviz DOT format.
func ExportDOT(g *AttackGraph) string {
	var b strings.Builder

	b.WriteString("digraph AttackGraph {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [fontname=\"Helvetica\" fontsize=10];\n")
	b.WriteString("  edge [fontname=\"Helvetica\" fontsize=8];\n\n")

	for _, n := range g.Nodes {
		shape := "box"
		color := "black"
		switch n.Type {
		case "finding":
			shape = "ellipse"
			switch n.Severity {
			case "CRITICAL":
				color = "red"
			case "HIGH":
				color = "orangered"
			case "MEDIUM":
				color = "orange"
			case "LOW":
				color = "gold"
			}
		case "chain":
			shape = "hexagon"
			color = "darkred"
		case "resource":
			shape = "box"
			color = "steelblue"
		case "technique":
			shape = "diamond"
			color = "purple"
		}

		label := dotEscape(n.Label)
		b.WriteString(fmt.Sprintf("  %q [label=%q shape=%s color=%s];\n",
			n.ID, label, shape, color))
	}

	b.WriteString("\n")

	for _, e := range g.Edges {
		style := "solid"
		edgeColor := "gray40"
		switch e.Type {
		case "triggers":
			edgeColor = "red"
		case "enables":
			edgeColor = "orange"
			style = "dashed"
		case "affects":
			edgeColor = "steelblue"
		case "uses_technique":
			edgeColor = "purple"
			style = "dotted"
		}

		label := dotEscape(e.Label)
		b.WriteString(fmt.Sprintf("  %q -> %q [label=%q color=%s style=%s];\n",
			e.Source, e.Target, label, edgeColor, style))
	}

	b.WriteString("}\n")
	return b.String()
}

// dotEscape replaces characters that would break DOT label strings.
func dotEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
