package drift

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// Analyzer performs permission-drift analysis by comparing the set of
// actions each principal is GRANTED (via RBAC role assignments) against
// the set of actions it has actually USED in the Azure Activity Log over
// some time window. Unused permissions represent an oversized blast
// radius and are exactly what least-privilege auditing is meant to
// surface.
type Analyzer struct {
	activityLog []models.ActivityEvent
	resolver    *RoleResolver
}

// NewAnalyzer constructs an Analyzer using the embedded built-in role
// catalogue only. For live ARM lookups use NewAnalyzerWithResolver.
func NewAnalyzer(activityLog []models.ActivityEvent) *Analyzer {
	resolver, _ := NewRoleResolver(nil, "")
	return &Analyzer{
		activityLog: activityLog,
		resolver:    resolver,
	}
}

// NewAnalyzerWithResolver lets callers inject a resolver that has
// live ARM credentials so unknown role definitions can be fetched.
func NewAnalyzerWithResolver(activityLog []models.ActivityEvent, resolver *RoleResolver) *Analyzer {
	return &Analyzer{
		activityLog: activityLog,
		resolver:    resolver,
	}
}

// Analyze inspects every role assignment in the snapshot, resolves the
// referenced role definition (live ARM → embedded catalogue → wildcard
// fallback), expands any wildcard actions against a representative
// operation catalogue, then compares the expanded "granted" set to the
// actions actually observed in the activity log for that principal.
// One DriftFinding is emitted per role assignment, sorted worst-first.
func (a *Analyzer) Analyze(snapshot *models.AzureSnapshot, days int) []models.DriftFinding {
	if snapshot == nil {
		return nil
	}
	if a.resolver == nil {
		// Defensive: NewAnalyzer always builds one, but a caller could
		// construct Analyzer{} directly. Rebuild from the embedded file.
		if r, err := NewRoleResolver(nil, ""); err == nil {
			a.resolver = r
		}
	}

	var cutoff time.Time
	if days > 0 {
		cutoff = time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	}

	// Index activity-log events by caller for fast lookup. The "caller"
	// field is typically an object ID or UPN depending on the source.
	type callerEvents struct {
		operations map[string]struct{}
		lastSeen   time.Time
	}
	byCaller := make(map[string]*callerEvents)
	for _, e := range a.activityLog {
		if days > 0 && e.Timestamp.Before(cutoff) {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(e.Caller))
		if key == "" {
			continue
		}
		ce, ok := byCaller[key]
		if !ok {
			ce = &callerEvents{operations: map[string]struct{}{}}
			byCaller[key] = ce
		}
		if e.OperationName != "" {
			ce.operations[e.OperationName] = struct{}{}
		}
		if e.Timestamp.After(ce.lastSeen) {
			ce.lastSeen = e.Timestamp
		}
	}

	// Build principal-id → display name / type maps so we can emit
	// friendlier identity details on the drift finding.
	principalNames := buildPrincipalNameMap(snapshot)
	principalTypes := buildPrincipalTypeMap(snapshot)

	findings := make([]models.DriftFinding, 0, len(snapshot.Identity.RoleAssignments))

	for _, ra := range snapshot.Identity.RoleAssignments {
		granted, resolvedRoleName, fallbackNote := a.grantedActionsFor(ra)

		// Decide which role name to display: prefer the resolver's
		// answer (canonical), then the assignment's stored name, then
		// the role definition GUID as a last resort.
		displayRoleName := resolvedRoleName
		if displayRoleName == "" {
			displayRoleName = ra.RoleName
		}
		if displayRoleName == "" {
			displayRoleName = lastSegment(ra.RoleDefinitionID)
		}
		if displayRoleName == "" {
			displayRoleName = "(unknown role)"
		}
		roleResolved := resolvedRoleName != ""

		// Find activity either under principal ID or principal name.
		pid := strings.ToLower(strings.TrimSpace(ra.PrincipalID))
		pname := strings.ToLower(strings.TrimSpace(principalNames[ra.PrincipalID]))

		ops := map[string]struct{}{}
		var lastSeen time.Time
		if ce, ok := byCaller[pid]; ok {
			for k := range ce.operations {
				ops[k] = struct{}{}
			}
			if ce.lastSeen.After(lastSeen) {
				lastSeen = ce.lastSeen
			}
		}
		if pname != "" {
			if ce, ok := byCaller[pname]; ok {
				for k := range ce.operations {
					ops[k] = struct{}{}
				}
				if ce.lastSeen.After(lastSeen) {
					lastSeen = ce.lastSeen
				}
			}
		}

		used := make([]string, 0, len(ops))
		for k := range ops {
			used = append(used, k)
		}
		sort.Strings(used)

		unused := diffActions(granted, used)
		unusedPct := computeUnusedPercentage(granted, used)
		blast := blastRadiusFor(unusedPct)

		ptype := principalTypes[ra.PrincipalID]
		if ptype == "" {
			ptype = ra.PrincipalType
		}

		lastActivity := ""
		if !lastSeen.IsZero() {
			lastActivity = lastSeen.Format(time.RFC3339)
		}

		displayName := principalNames[ra.PrincipalID]
		if displayName == "" {
			displayName = ra.PrincipalID
		}

		findings = append(findings, models.DriftFinding{
			IdentityARN:        ra.PrincipalID,
			IdentityName:       displayName,
			IdentityType:       ptype,
			RoleName:           displayRoleName,
			RoleResolved:       roleResolved,
			AnalysisWindowDays: days,
			GrantedActions:     granted,
			UsedActions:        used,
			UnusedActions:      unused,
			UnusedPercentage:   round1(unusedPct),
			BlastRadius:        blast,
			LastActivity:       lastActivity,
			Recommendation:     recommendation(used, displayRoleName, days, fallbackNote),
		})
	}

	// Sort worst blast radius first so the report highlights the
	// accounts most in need of attention.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].UnusedPercentage != findings[j].UnusedPercentage {
			return findings[i].UnusedPercentage > findings[j].UnusedPercentage
		}
		return blastRadiusRank(findings[i].BlastRadius) < blastRadiusRank(findings[j].BlastRadius)
	})

	return findings
}

// grantedActionsFor returns the expanded action set for a role
// assignment along with the resolved role display name (when found)
// and an optional human-readable note for the recommendation.
//
// Resolution order: live ARM by role-definition ID → embedded
// catalogue by name → wildcard fallback ["*"].
func (a *Analyzer) grantedActionsFor(ra models.RoleAssignment) (actions []string, resolvedName string, note string) {
	if a.resolver != nil {
		if rd, err := a.resolver.Resolve(context.Background(), ra.RoleDefinitionID); err == nil && rd != nil {
			return a.resolver.ExpandActions(rd), rd.Name, ""
		}
		if rd := a.resolver.ResolveByName(ra.RoleName); rd != nil {
			return a.resolver.ExpandActions(rd), rd.Name, ""
		}
	}
	return []string{"*"}, "", "role definition unavailable — defaulting to wildcard"
}

// diffActions returns the actions in granted that the caller never used.
// Wildcard granted entries are compared loosely: if "*" is granted and
// no action was used, the full granted list is considered unused. Any
// wildcard that matches at least one used action is considered "used".
func diffActions(granted, used []string) []string {
	usedSet := make(map[string]struct{}, len(used))
	for _, u := range used {
		usedSet[u] = struct{}{}
	}
	out := []string{}
	for _, g := range granted {
		if wildcardMatchAny(g, used) {
			continue
		}
		if _, ok := usedSet[g]; ok {
			continue
		}
		out = append(out, g)
	}
	return out
}

// wildcardMatchAny reports whether the granted action pattern (which
// may contain one or more '*' wildcards) matches any of the used
// actions.
func wildcardMatchAny(pattern string, used []string) bool {
	if !strings.Contains(pattern, "*") {
		return false
	}
	for _, u := range used {
		if wildcardMatch(pattern, u) {
			return true
		}
	}
	return false
}

// wildcardMatch is a minimal glob matcher for Azure RBAC actions. It
// supports '*' matching any run of characters and is case-insensitive.
func wildcardMatch(pattern, s string) bool {
	pattern = strings.ToLower(pattern)
	s = strings.ToLower(s)
	parts := strings.Split(pattern, "*")
	idx := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 && !strings.HasPrefix(s, part) {
			return false
		}
		found := strings.Index(s[idx:], part)
		if found == -1 {
			return false
		}
		idx += found + len(part)
	}
	if len(parts) > 0 && parts[len(parts)-1] != "" {
		if !strings.HasSuffix(s, parts[len(parts)-1]) {
			return false
		}
	}
	return true
}

// computeUnusedPercentage is the fraction of granted actions that were
// never observed in the activity log. When the granted set is ["*"]
// (the defensive fallback when a role can't be resolved) we approximate
// the ratio by 100% if the principal has no activity, or 50% if it has
// some activity. For normal expanded sets we count exact+wildcard
// matches and divide.
func computeUnusedPercentage(granted, used []string) float64 {
	if len(granted) == 0 {
		return 0
	}
	if len(granted) == 1 && granted[0] == "*" {
		if len(used) == 0 {
			return 100
		}
		return 50
	}
	unused := 0
	for _, g := range granted {
		if wildcardMatchAny(g, used) {
			continue
		}
		found := false
		for _, u := range used {
			if strings.EqualFold(g, u) {
				found = true
				break
			}
		}
		if !found {
			unused++
		}
	}
	return float64(unused) / float64(len(granted)) * 100
}

// blastRadiusFor maps an unused-percentage to a blast-radius bucket.
func blastRadiusFor(pct float64) string {
	switch {
	case pct >= 80:
		return "CRITICAL"
	case pct >= 60:
		return "HIGH"
	case pct >= 40:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func blastRadiusRank(b string) int {
	switch b {
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

// recommendation builds the human-facing next-step string that appears
// on every drift finding. The message always names the analysis window
// (number of days of Activity Log inspected) and the specific role
// assignment so the operator has full context.
//
// When `used` is empty we tell the operator the principal has had no
// observed activity in the analysis window and recommend removing the
// assignment. When `used` is populated we emit a copy-paste-ready list
// of up to 10 actually-used actions for building a least-privilege
// custom role. An optional `note` (e.g. "role definition unavailable")
// is appended in parentheses so the operator knows when to be cautious
// about the analysis itself.
func recommendation(used []string, roleName string, analysisDays int, note string) string {
	if roleName == "" {
		roleName = "(unknown role)"
	}
	windowPhrase := fmt.Sprintf("the last %d days", analysisDays)
	if analysisDays <= 0 {
		windowPhrase = "the full Activity Log window collected by ARGUS"
	}

	var base string
	if len(used) == 0 {
		base = fmt.Sprintf(
			"This principal has had NO observed activity in %s. Consider removing the '%s' role assignment entirely, "+
				"or confirm whether it is a break-glass / disaster-recovery identity that should be exempt. "+
				"Note: ARGUS only analyses Azure Activity Log events visible to the scanning identity within this window — "+
				"longer-lived dormant access (control-plane only, data-plane only, or activity older than %d days) "+
				"will not appear here.",
			windowPhrase, roleName, maxInt(analysisDays, 0),
		)
	} else {
		display := used
		if len(display) > 10 {
			display = display[:10]
		}
		base = fmt.Sprintf(
			"Over %s this principal used %d distinct action(s). Scope its '%s' assignment to a custom role containing only: %s",
			windowPhrase, len(used), roleName, strings.Join(display, ", "),
		)
		if len(used) > 10 {
			base += fmt.Sprintf(" (… and %d more — see the full used_actions list in the JSON output)", len(used)-10)
		}
	}
	if note != "" {
		base += " (" + note + ")"
	}
	return base
}

// lastSegment returns the trailing path segment of a slash-delimited
// string. Used to extract the role definition GUID from a role
// definition resource ID like
// "/subscriptions/.../providers/Microsoft.Authorization/roleDefinitions/<guid>".
func lastSegment(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "/"); i >= 0 && i+1 < len(s) {
		return s[i+1:]
	}
	return s
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// buildPrincipalNameMap returns an object-id → display-name map
// covering users, service principals and managed identities.
func buildPrincipalNameMap(snapshot *models.AzureSnapshot) map[string]string {
	out := make(map[string]string)
	for _, u := range snapshot.Identity.Users {
		if u.ID != "" {
			out[u.ID] = u.DisplayName
		}
	}
	for _, sp := range snapshot.Identity.ServicePrincipals {
		if sp.ID != "" {
			out[sp.ID] = sp.DisplayName
		}
	}
	for _, mi := range snapshot.Identity.ManagedIdentities {
		if mi.PrincipalID != "" {
			out[mi.PrincipalID] = mi.Name
		}
	}
	return out
}

// buildPrincipalTypeMap returns an object-id → principal-type map.
func buildPrincipalTypeMap(snapshot *models.AzureSnapshot) map[string]string {
	out := make(map[string]string)
	for _, u := range snapshot.Identity.Users {
		if u.ID != "" {
			out[u.ID] = "User"
		}
	}
	for _, sp := range snapshot.Identity.ServicePrincipals {
		if sp.ID != "" {
			out[sp.ID] = "ServicePrincipal"
		}
	}
	for _, mi := range snapshot.Identity.ManagedIdentities {
		if mi.PrincipalID != "" {
			out[mi.PrincipalID] = "ManagedIdentity"
		}
	}
	return out
}

// round1 rounds a float to one decimal place.
func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
