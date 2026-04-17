// Package pathfinder builds a directed graph of principals, scopes, and
// resources from an Azure snapshot and walks it to discover attack paths
// the hand-authored chain library would miss. Where internal/engine
// correlator.go encodes 51 specific patterns ("if finding X + Y + Z fire
// together, emit CHAIN-N"), the pathfinder is pattern-free: it starts
// from weak entry points (guest users, no-MFA accounts, SPs whose
// credentials never expire) and uses weighted BFS to find graphs of
// role-assignment + membership edges that reach a high-value target.
// Every such walk becomes a DISC-<n> attack chain rendered alongside
// the hand-authored ones.
package pathfinder

import (
	"fmt"
	"sort"
	"strings"
)

// NodeKind is the category of a graph node. The kind controls which
// edge types the builder can attach to it and how the pathfinder scores
// a walk that crosses it.
type NodeKind string

const (
	KindUser         NodeKind = "user"
	KindGuestUser    NodeKind = "guest_user"
	KindGroup        NodeKind = "group"
	KindSP           NodeKind = "service_principal"
	KindApp          NodeKind = "app_registration"
	KindMI           NodeKind = "managed_identity"
	KindSubscription NodeKind = "subscription"
	KindResourceGroup NodeKind = "resource_group"
	KindResource     NodeKind = "resource"
	KindExternal     NodeKind = "external" // conceptual root — the internet
)

// Node is a graph node. IDs are unique across kinds. Label is a human
// name shown in the rendered chain narrative.
type Node struct {
	ID         string
	Kind       NodeKind
	Label      string
	Weakness   string // non-empty = this principal / resource is a soft entry point
	HighValue  bool   // this node should be treated as an attack destination
	Attributes map[string]string
}

// EdgeKind is the category of a graph edge. The kind also dictates the
// baseline weight applied to any walk that traverses it.
type EdgeKind string

const (
	EdgeMemberOf     EdgeKind = "member_of"
	EdgeOwnsApp      EdgeKind = "owns_app"
	EdgeCredFor      EdgeKind = "is_credential_for"
	EdgeHasRole      EdgeKind = "has_role"
	EdgeAssignedMI   EdgeKind = "assigned_mi"
	EdgeContains     EdgeKind = "contains"
	EdgeExposesTo    EdgeKind = "exposes_to"
)

// Edge is a directed edge from From → To. Role captures the RBAC role
// name on an EdgeHasRole edge (empty for other kinds). Weight is the
// per-edge cost a pathfinder accrues when traversing it — high weight
// = high attacker power, so pathfinding maximises weight rather than
// minimising it. AssignmentState distinguishes PIM-eligible from PIM-
// active and permanent assignments on EdgeHasRole edges:
//
//	""         — permanent direct assignment (default)
//	"Active"   — PIM schedule is currently activated (equivalent power)
//	"Eligible" — PIM eligible (attacker must activate first; slight
//	             confidence penalty downstream)
type Edge struct {
	From            string
	To              string
	Kind            EdgeKind
	Role            string
	Weight          int
	AssignmentState string
}

// Graph is a directed graph indexed by node ID. Edges are stored on the
// source node so that forward traversal from any node is O(1) in the
// number of out-edges.
type Graph struct {
	Nodes     map[string]*Node
	OutEdges  map[string][]*Edge
}

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{
		Nodes:    make(map[string]*Node),
		OutEdges: make(map[string][]*Edge),
	}
}

// AddNode inserts or overrides a node. The insertion is idempotent —
// callers may add the same node multiple times without error.
func (g *Graph) AddNode(n *Node) {
	if n == nil || n.ID == "" {
		return
	}
	g.Nodes[n.ID] = n
}

// AddEdge appends an edge. If either endpoint is not a known node the
// edge is dropped (silently) so callers can be naïve about ordering.
func (g *Graph) AddEdge(e *Edge) {
	if e == nil || e.From == "" || e.To == "" {
		return
	}
	if _, ok := g.Nodes[e.From]; !ok {
		return
	}
	if _, ok := g.Nodes[e.To]; !ok {
		return
	}
	g.OutEdges[e.From] = append(g.OutEdges[e.From], e)
}

// Neighbours returns a copy of the out-edges of the given node, sorted
// by descending weight. Sorting makes subsequent BFS results more
// deterministic and biased toward the most privileged walks first.
func (g *Graph) Neighbours(id string) []*Edge {
	edges := g.OutEdges[id]
	if len(edges) == 0 {
		return nil
	}
	out := make([]*Edge, len(edges))
	copy(out, edges)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Weight > out[j].Weight
	})
	return out
}

// Stats returns a summary of the graph's size. Used for telemetry /
// debug logging in the scan pipeline.
func (g *Graph) Stats() string {
	edgeCount := 0
	byKind := map[NodeKind]int{}
	for _, n := range g.Nodes {
		byKind[n.Kind]++
	}
	for _, es := range g.OutEdges {
		edgeCount += len(es)
	}
	parts := []string{fmt.Sprintf("%d nodes, %d edges", len(g.Nodes), edgeCount)}
	kinds := make([]string, 0, len(byKind))
	for k, n := range byKind {
		kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(kinds)
	parts = append(parts, strings.Join(kinds, " "))
	return strings.Join(parts, " | ")
}

// PrincipalNodeID returns the canonical node ID for an Azure AD
// principal so that the builder and pathfinder agree on naming.
// Guest users share the "user:" namespace with regular users so that
// role assignments (which only carry PrincipalType=User for both) can
// bind to the right node without caller-side conditionals.
func PrincipalNodeID(kind NodeKind, objectID string) string {
	prefix := string(kind)
	switch kind {
	case KindUser, KindGuestUser:
		prefix = "user"
	case KindSP:
		prefix = "sp"
	case KindMI:
		prefix = "mi"
	case KindApp:
		prefix = "app"
	case KindGroup:
		prefix = "group"
	}
	return fmt.Sprintf("%s:%s", prefix, objectID)
}

// ScopeNodeID returns the canonical node ID for an Azure scope
// (subscription, resource group, or resource).
func ScopeNodeID(scope string) string {
	return fmt.Sprintf("scope:%s", strings.ToLower(scope))
}
