package pathfinder

import (
	"sort"
)

// Path is one attack path through the graph, source at Nodes[0] and
// destination at Nodes[len-1]. Edges[i] is the edge that connects
// Nodes[i] to Nodes[i+1]. TotalWeight is the sum of all edge weights
// along the walk — the pathfinder prefers higher weights because they
// represent more attacker power.
type Path struct {
	Nodes       []*Node
	Edges       []*Edge
	TotalWeight int
}

// FindOptions controls pathfinder behaviour.
type FindOptions struct {
	// MaxHops caps path length. The graph is small, but cyclic edges
	// (sub → rg → resource → mi → sub) can still balloon the search.
	MaxHops int
	// MinWeight drops paths whose accumulated weight is below this
	// threshold. A walk from Internet → resource through only a Reader
	// role is not interesting.
	MinWeight int
	// TopK bounds the number of paths returned after ranking.
	TopK int
}

// DefaultFindOptions is the out-of-the-box configuration used when no
// explicit options are supplied to Discover.
func DefaultFindOptions() FindOptions {
	return FindOptions{MaxHops: 6, MinWeight: 8, TopK: 10}
}

// Discover enumerates paths from every weak entry node to every
// high-value destination node. It is deliberately breadth-first rather
// than Dijkstra: path counts are small (hundreds in a realistic
// environment) and we want the N highest-weight distinct paths, which
// a bounded BFS can sort at the end just as cheaply.
func Discover(g *Graph, opts FindOptions) []Path {
	if opts.MaxHops == 0 {
		opts = DefaultFindOptions()
	}

	sources := collectEntries(g)
	destinations := collectTargets(g)
	if len(sources) == 0 || len(destinations) == 0 {
		return nil
	}
	destSet := make(map[string]struct{}, len(destinations))
	for _, d := range destinations {
		destSet[d.ID] = struct{}{}
	}

	var paths []Path
	for _, start := range sources {
		walked := bfs(g, start, destSet, opts)
		paths = append(paths, walked...)
	}

	paths = dedupe(paths)
	sort.SliceStable(paths, func(i, j int) bool {
		return paths[i].TotalWeight > paths[j].TotalWeight
	})
	if opts.TopK > 0 && len(paths) > opts.TopK {
		paths = paths[:opts.TopK]
	}
	return paths
}

// bfs walks out-edges from start until it hits a destination, giving
// up after MaxHops. Each path is recorded only once — the queue state
// keeps a full slice of visited nodes so the search does not loop.
func bfs(g *Graph, start *Node, destSet map[string]struct{}, opts FindOptions) []Path {
	type frontier struct {
		nodes  []*Node
		edges  []*Edge
		weight int
	}

	var out []Path
	queue := []frontier{{nodes: []*Node{start}}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if len(cur.nodes) > opts.MaxHops {
			continue
		}

		head := cur.nodes[len(cur.nodes)-1]

		// Accept: landed on a target, path has at least one edge, and
		// the minimum privilege bar is met.
		if len(cur.edges) > 0 {
			if _, ok := destSet[head.ID]; ok && cur.weight >= opts.MinWeight {
				out = append(out, Path{
					Nodes:       append([]*Node{}, cur.nodes...),
					Edges:       append([]*Edge{}, cur.edges...),
					TotalWeight: cur.weight,
				})
				// Don't extend past a destination — every reachable target
				// is its own chain.
				continue
			}
		}

		for _, e := range g.Neighbours(head.ID) {
			// Reject revisits — this keeps the search finite even with
			// contains / assigned_mi cycles.
			if containsNode(cur.nodes, e.To) {
				continue
			}
			next, ok := g.Nodes[e.To]
			if !ok {
				continue
			}
			nweight := cur.weight + edgeBaseWeight(e)
			queue = append(queue, frontier{
				nodes:  append(append([]*Node{}, cur.nodes...), next),
				edges:  append(append([]*Edge{}, cur.edges...), e),
				weight: nweight,
			})
		}
	}
	return out
}

// edgeBaseWeight returns the walking cost of a single edge. EdgeHasRole
// carries its own role-specific weight already; other kinds contribute
// structural information with a small fixed weight so the pathfinder
// can still compare multi-hop walks.
func edgeBaseWeight(e *Edge) int {
	if e.Weight > 0 {
		return e.Weight
	}
	switch e.Kind {
	case EdgeMemberOf, EdgeCredFor, EdgeAssignedMI, EdgeContains, EdgeOwnsApp:
		return 0
	case EdgeExposesTo:
		return 3
	}
	return 1
}

// collectEntries returns nodes the pathfinder should try as starting
// points. A weak user (guest, no MFA, etc.), a flagged SP, or the
// Internet root node all qualify; any of them can be the source of an
// intrusion narrative.
func collectEntries(g *Graph) []*Node {
	var out []*Node
	for _, n := range g.Nodes {
		switch {
		case n.Kind == KindExternal:
			out = append(out, n)
		case n.Kind == KindGuestUser:
			out = append(out, n)
		case n.Kind == KindUser && n.Weakness != "":
			out = append(out, n)
		case n.Kind == KindSP && n.Weakness != "":
			out = append(out, n)
		}
	}
	return out
}

// collectTargets returns nodes that should end a discovered chain — any
// resource node flagged high-value plus the subscription root (because
// a path that reaches the subscription scope can read everything in it).
func collectTargets(g *Graph) []*Node {
	var out []*Node
	for _, n := range g.Nodes {
		if n.HighValue {
			out = append(out, n)
		}
		if n.Kind == KindSubscription {
			out = append(out, n)
		}
	}
	return out
}

// containsNode reports whether the visited-slice already contains the
// named ID. Used to prevent cycles during BFS.
func containsNode(visited []*Node, id string) bool {
	for _, n := range visited {
		if n.ID == id {
			return true
		}
	}
	return false
}

// dedupe drops paths whose (source, destination, first-role) tuple is
// identical to another, higher-weight path. Without this the top-K list
// fills with near-duplicates that all end at the same key vault via
// slightly different RG hops.
func dedupe(paths []Path) []Path {
	sort.SliceStable(paths, func(i, j int) bool {
		return paths[i].TotalWeight > paths[j].TotalWeight
	})
	seen := map[string]struct{}{}
	out := make([]Path, 0, len(paths))
	for _, p := range paths {
		if len(p.Nodes) < 2 {
			continue
		}
		firstRole := ""
		for _, e := range p.Edges {
			if e.Kind == EdgeHasRole {
				firstRole = e.Role
				break
			}
		}
		key := p.Nodes[0].ID + "→" + p.Nodes[len(p.Nodes)-1].ID + "::" + firstRole
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}
