package pathfinder

import (
	"fmt"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// DiscoverChains is the one-call integration point. Given a snapshot
// and the findings the OPA engine produced, it builds the graph, runs
// the pathfinder, and returns the discovered paths as AttackChain
// objects with IDs prefixed DISC- so renderers can distinguish them
// from the 51 hand-authored patterns.
func DiscoverChains(snap *models.AzureSnapshot, findings []models.Finding) []models.AttackChain {
	return DiscoverChainsWithOptions(snap, findings, DefaultFindOptions())
}

// DiscoverChainsWithOptions is DiscoverChains with explicit pathfinder
// options, exposed mainly for tests that need deterministic control over
// MaxHops and MinWeight.
func DiscoverChainsWithOptions(snap *models.AzureSnapshot, findings []models.Finding, opts FindOptions) []models.AttackChain {
	graph := BuildGraph(snap, findings)
	paths := Discover(graph, opts)
	graphLimited := snap != nil && snap.GraphPermissionsLimited
	chains := make([]models.AttackChain, 0, len(paths))
	for i, p := range paths {
		chains = append(chains, pathToChain(i+1, p, findings, graphLimited))
	}
	return chains
}

// pathToChain renders a single walk as an AttackChain. The narrative
// is assembled by concatenating a per-edge phrase; the steps array
// follows the same schema as every other chain so downstream reporters
// (HTML, JSON, SARIF) do not need DISC-specific rendering code.
func pathToChain(idx int, p Path, findings []models.Finding, graphLimited bool) models.AttackChain {
	chain := models.AttackChain{
		ID:         fmt.Sprintf("DISC-%03d", idx),
		Title:      chainTitle(p),
		Severity:   severityForPath(p),
		Likelihood: likelihoodForPath(p),
		Confidence: confidenceForPath(p, graphLimited),
	}

	chain.Narrative = renderNarrative(p)
	chain.EnvironmentSummary = fmt.Sprintf(
		"Graph pathfinder found this walk through your RBAC + identity state (%d-hop, total privilege weight %d). "+
			"It is not in the hand-authored library — pattern-based detections missed it.",
		len(p.Edges), p.TotalWeight,
	)

	// Steps — one step per edge in the walk.
	for i, e := range p.Edges {
		fromNode := p.Nodes[i]
		toNode := p.Nodes[i+1]
		step := models.ChainStep{
			Number:    i + 1,
			Actor:     shortLabel(fromNode),
			Action:    edgePhrase(e, toNode),
			Technical: fmt.Sprintf("%s → %s via %s", fromNode.ID, toNode.ID, e.Kind),
			Technique: edgeTechnique(e),
			EnabledBy: findingEnabler(fromNode, findings),
			Gain:      edgeGain(e, toNode),
		}
		chain.Steps = append(chain.Steps, step)
	}

	// Blast radius is crude for discovered chains — we don't know the
	// specific data classification of the target, just that a weak
	// actor reached a high-value scope.
	target := p.Nodes[len(p.Nodes)-1]
	chain.BlastRadius = models.BlastRadiusDetail{
		InitialAccess:      initialAccessFor(p.Nodes[0]),
		LateralMovement:    fmt.Sprintf("%d graph hops", len(p.Edges)),
		MaxPrivilege:       highestRole(p.Edges),
		DataAtRisk:         []string{target.Label},
		EstimatedScopePerc: "single scope",
	}

	// MinimalFixSet: break any single edge to break the chain. The
	// recommendation lists the specific RBAC assignment with highest
	// weight — that is the most leverage-per-fix.
	chain.MinimalFixSet, chain.PriorityFix, chain.BreakingNote = recommendFix(p)

	// Carry the resource IDs the walk touches so downstream reports
	// can link back to them.
	for _, n := range p.Nodes {
		if n.Kind == KindResource || n.Kind == KindSubscription {
			// strip "scope:" prefix
			id := strings.TrimPrefix(n.ID, "scope:")
			chain.AffectedResources = append(chain.AffectedResources, id)
		}
	}

	chain.KillChainPhase = "Privilege Escalation"
	chain.MITRETechnique = "T1078" // Valid Accounts — the umbrella for most privilege-escalation-via-identity chains
	chain.MITRETactic = "Privilege Escalation"

	return chain
}

func chainTitle(p Path) string {
	if len(p.Nodes) < 2 {
		return "Discovered attack path"
	}
	start := p.Nodes[0]
	end := p.Nodes[len(p.Nodes)-1]
	return fmt.Sprintf("%s → %s (%d-hop RBAC walk)", shortLabel(start), shortLabel(end), len(p.Edges))
}

// severityForPath grades a discovered walk. A single privilege-granting
// edge (Owner, UAA, RBAC Admin) is already a critical finding on its
// own — the pathfinder surfaces it because no hand-authored chain
// required the structural context ("this user can grant themselves
// anything") to bias on. Scaling by path length alone understates
// severity, so we gate on the maximum role weight on the walk and the
// kind of the entry point.
func severityForPath(p Path) string {
	maxRoleWeight := 0
	for _, e := range p.Edges {
		if e.Kind == EdgeHasRole && e.Weight > maxRoleWeight {
			maxRoleWeight = e.Weight
		}
	}
	entry := p.Nodes[0]

	// Guest account with ANY privilege-granting role is tenant-takeover
	// grade — promote straight to CRITICAL.
	if entry.Kind == KindGuestUser && maxRoleWeight >= 10 {
		return "CRITICAL"
	}
	// Anyone with a privilege-granting role (Owner / UAA / RBAC Admin)
	// is a high finding at minimum.
	if maxRoleWeight >= 10 {
		return "HIGH"
	}
	// Strong write role (Contributor, KV Admin, AKS Cluster Admin).
	if maxRoleWeight >= 8 {
		return "MEDIUM"
	}
	return "LOW"
}

func likelihoodForPath(p Path) string {
	// Likelihood tracks how hard the entry side is to compromise.
	// A guest or no-MFA entry is realistic — "High". An internal
	// account without flagged weakness is less so.
	entry := p.Nodes[0]
	switch entry.Kind {
	case KindExternal, KindGuestUser:
		return "High"
	case KindUser, KindSP:
		if entry.Weakness != "" {
			return "High"
		}
		return "Medium"
	}
	return "Low"
}

// confidenceForPath grades how certain we are that the discovered walk
// is actually exploitable in practice. The inputs:
//
//   * Maximum role weight on the walk — a direct Owner edge is stronger
//     evidence than a chain of Reader edges.
//   * Path length — shorter = higher confidence (less ambiguity about
//     whether each hop is actually traversable by the entry principal).
//   * Known weakness at entry — a principal we explicitly flagged (guest
//     + no-MFA, SP with non-expiring cred) is a higher-confidence entry
//     than an internal user with no flagged issue.
//   * Graph permissions limited — when identity collection returned
//     403s, our view of the role graph is incomplete and confidence in
//     any discovered walk drops by one bucket.
//
// Returns "High", "Medium", or "Low".
func confidenceForPath(p Path, graphLimited bool) string {
	score := 0

	maxRoleWeight := 0
	hasEligible := false
	for _, e := range p.Edges {
		if e.Kind == EdgeHasRole && e.Weight > maxRoleWeight {
			maxRoleWeight = e.Weight
		}
		if e.Kind == EdgeHasRole && e.AssignmentState == "Eligible" {
			hasEligible = true
		}
	}
	switch {
	case maxRoleWeight >= 10:
		score += 3
	case maxRoleWeight >= 8:
		score += 2
	case maxRoleWeight >= 6:
		score += 1
	}

	// Shorter paths are more reliable; cap the bonus so we don't
	// over-reward single-edge walks that happen to be Reader-only.
	switch len(p.Edges) {
	case 1:
		score += 2
	case 2, 3:
		score += 1
	}

	if p.Nodes[0].Weakness != "" {
		score += 1
	}

	if graphLimited {
		score -= 2
	}

	// PIM Eligible introduces an activation step between compromise
	// and exercise. The path is still real — a motivated attacker can
	// satisfy MFA+justification — but it's strictly less certain than
	// a permanent or currently-active edge.
	if hasEligible {
		score -= 1
	}

	switch {
	case score >= 5:
		return "High"
	case score >= 3:
		return "Medium"
	default:
		return "Low"
	}
}

// severityForWeight is retained for backwards compatibility with the
// tests; production code should use severityForPath instead.
func severityForWeight(w int) string {
	switch {
	case w >= 20:
		return "CRITICAL"
	case w >= 12:
		return "HIGH"
	case w >= 8:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func renderNarrative(p Path) string {
	var b strings.Builder
	b.WriteString("Graph pathfinder discovered this walk: ")
	for i, n := range p.Nodes {
		if i > 0 {
			e := p.Edges[i-1]
			b.WriteString(" → ")
			b.WriteString(edgeLabel(e))
			b.WriteString(" → ")
		}
		b.WriteString(shortLabel(n))
	}
	b.WriteString(".")
	if p.Nodes[0].Weakness != "" {
		b.WriteString(fmt.Sprintf(" Entry weakness: %s.", p.Nodes[0].Weakness))
	}
	return b.String()
}

func shortLabel(n *Node) string {
	if n == nil {
		return "?"
	}
	if n.Label != "" {
		return n.Label
	}
	return n.ID
}

func edgeLabel(e *Edge) string {
	switch e.Kind {
	case EdgeHasRole:
		if e.AssignmentState == "Eligible" {
			return fmt.Sprintf("[role:%s (PIM eligible)]", e.Role)
		}
		if e.AssignmentState == "Active" {
			return fmt.Sprintf("[role:%s (PIM active)]", e.Role)
		}
		return fmt.Sprintf("[role:%s]", e.Role)
	case EdgeMemberOf:
		return "[member of]"
	case EdgeCredFor:
		return "[credential for]"
	case EdgeAssignedMI:
		return "[runs as MI]"
	case EdgeContains:
		return "[contains]"
	case EdgeExposesTo:
		return "[exposes]"
	case EdgeOwnsApp:
		return "[owns app]"
	}
	return string(e.Kind)
}

func edgePhrase(e *Edge, to *Node) string {
	switch e.Kind {
	case EdgeHasRole:
		switch e.AssignmentState {
		case "Eligible":
			return fmt.Sprintf("activates and exercises %q role on %s (PIM eligible)", e.Role, shortLabel(to))
		case "Active":
			return fmt.Sprintf("exercises %q role on %s (PIM currently active)", e.Role, shortLabel(to))
		default:
			return fmt.Sprintf("exercises %q role on %s", e.Role, shortLabel(to))
		}
	case EdgeMemberOf:
		return fmt.Sprintf("inherits permissions through group membership %s", shortLabel(to))
	case EdgeCredFor:
		return fmt.Sprintf("authenticates as %s", shortLabel(to))
	case EdgeAssignedMI:
		return fmt.Sprintf("runs as managed identity %s", shortLabel(to))
	case EdgeContains:
		return fmt.Sprintf("reaches scope %s", shortLabel(to))
	case EdgeExposesTo:
		return fmt.Sprintf("contacts internet-exposed surface %s", shortLabel(to))
	case EdgeOwnsApp:
		return fmt.Sprintf("owns app registration %s", shortLabel(to))
	}
	return fmt.Sprintf("traverses %s to %s", e.Kind, shortLabel(to))
}

func edgeTechnique(e *Edge) string {
	switch e.Kind {
	case EdgeHasRole:
		return "T1078.004" // Valid Accounts: Cloud Accounts
	case EdgeMemberOf:
		return "T1068"     // Exploitation for Privilege Escalation
	case EdgeCredFor:
		return "T1528"     // Steal Application Access Token
	case EdgeAssignedMI:
		return "T1078.004"
	case EdgeExposesTo:
		return "T1190"     // Exploit Public-Facing Application
	}
	return "T1078"
}

func edgeGain(e *Edge, to *Node) string {
	if e.Kind == EdgeHasRole {
		return fmt.Sprintf("%s at scope %s", e.Role, shortLabel(to))
	}
	if e.Kind == EdgeExposesTo {
		return "Network reachability"
	}
	return ""
}

func initialAccessFor(n *Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind {
	case KindExternal:
		return "Unauthenticated internet attacker"
	case KindGuestUser:
		return fmt.Sprintf("Compromised guest account (%s)", shortLabel(n))
	default:
		return fmt.Sprintf("Compromised %s (%s)", n.Kind, shortLabel(n))
	}
}

func highestRole(edges []*Edge) string {
	best := ""
	bestW := 0
	for _, e := range edges {
		if e.Kind != EdgeHasRole {
			continue
		}
		if e.Weight > bestW {
			best = e.Role
			bestW = e.Weight
		}
	}
	return best
}

func findingEnabler(n *Node, findings []models.Finding) string {
	if n == nil || n.Weakness == "" {
		return ""
	}
	// Try to match a finding whose title matches any weakness phrase.
	for _, f := range findings {
		if strings.Contains(n.Weakness, f.Title) || strings.Contains(f.Title, firstSegment(n.Weakness)) {
			return f.ID
		}
	}
	return ""
}

func firstSegment(s string) string {
	if idx := strings.Index(s, ";"); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}

func recommendFix(p Path) ([]string, string, string) {
	// The highest-weight role assignment on the walk is the single
	// edge whose removal most shrinks the chain's power. If there is
	// no role edge, recommend tightening the network exposure instead.
	bestIdx := -1
	bestWeight := 0
	for i, e := range p.Edges {
		if e.Kind == EdgeHasRole && e.Weight > bestWeight {
			bestIdx = i
			bestWeight = e.Weight
		}
	}
	if bestIdx < 0 {
		return nil,
			"Reduce internet exposure on the destination resource.",
			"Removing the public network edge breaks the only reachable walk to this resource."
	}
	from := p.Nodes[bestIdx]
	to := p.Nodes[bestIdx+1]
	e := p.Edges[bestIdx]
	fix := fmt.Sprintf(
		"Remove %s role assignment on %s from principal %s (lower-privilege role or group-based conditional assignment preferred).",
		e.Role, shortLabel(to), shortLabel(from),
	)
	note := fmt.Sprintf(
		"This edge contributes %d of the chain's total weight %d; removing it drops the walk below the privilege threshold.",
		e.Weight, p.TotalWeight,
	)
	return []string{fmt.Sprintf("remove-role:%s on %s", e.Role, shortLabel(to))}, fix, note
}
