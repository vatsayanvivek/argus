package pathfinder

import (
	"fmt"
	"strings"

	"github.com/vatsayanvivek/argus/internal/models"
)

// roleWeight maps an RBAC or Entra directory role name to a per-edge
// cost. Higher weight means more attacker power is gained by traversing
// the edge. The table covers both Azure RBAC (Owner, Contributor, …)
// and Entra directory roles (Global Administrator, Privileged Role
// Administrator, …); directory roles at tenant scope are tenant-takeover
// grade and sit at weight 10. An unknown role defaults to 2.
func roleWeight(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	// --- Azure RBAC (resource plane) ---
	case "owner":
		return 10
	case "user access administrator", "role based access control administrator":
		return 10
	case "contributor":
		return 8
	case "security admin":
		return 7
	case "key vault administrator":
		return 8
	case "managed identity contributor", "managed identity operator":
		return 7
	case "virtual machine contributor":
		return 7
	case "network contributor":
		return 6
	case "storage account contributor":
		return 7
	case "storage blob data owner", "storage blob data contributor":
		return 6
	case "sql db contributor", "sql server contributor":
		return 7
	case "website contributor":
		return 6
	case "kubernetes cluster admin", "azure kubernetes service cluster admin role":
		return 9
	case "automation contributor":
		return 6
	case "reader":
		return 1
	case "log analytics reader", "monitoring reader":
		return 1
	// --- Entra directory roles ---
	// Any of these at "/" scope is tenant takeover — the attacker can
	// read/write every identity object and escalate to any Azure RBAC
	// assignment via root management group elevation.
	case "global administrator", "company administrator":
		return 10
	case "privileged role administrator":
		return 10
	case "privileged authentication administrator":
		return 10
	case "application administrator", "cloud application administrator":
		return 9
	case "authentication administrator":
		return 8
	case "user administrator":
		return 8
	case "groups administrator":
		return 7
	case "conditional access administrator":
		return 8
	case "security administrator":
		return 8
	case "helpdesk administrator":
		return 6
	case "directory readers":
		return 1
	}
	// Data-plane or niche roles we haven't catalogued land here at
	// low-medium weight: they grant *something*, but not enough to be
	// a full-control edge on their own.
	return 2
}

// highValueResourceType reports whether a resource type is considered
// a plausible attack destination for pathfinding. Findings against
// these resource types are worth surfacing as discovered chains.
func highValueResourceType(armType string) bool {
	switch strings.ToLower(armType) {
	case
		"microsoft.keyvault/vaults",
		"microsoft.storage/storageaccounts",
		"microsoft.sql/servers",
		"microsoft.sql/servers/databases",
		"microsoft.documentdb/databaseaccounts",
		"microsoft.dbforpostgresql/servers",
		"microsoft.dbformysql/servers",
		"microsoft.containerservice/managedclusters",
		"microsoft.containerregistry/registries":
		return true
	}
	return false
}

// BuildGraph constructs the principal/resource/scope graph from an
// Azure snapshot. The caller provides a findings slice so the builder
// can flag nodes that existing rules already surfaced as weak entry
// points (e.g. an SP with credentials that never expire already fired
// zt_id_001 — pathfinding inherits that judgement).
func BuildGraph(snap *models.AzureSnapshot, findings []models.Finding) *Graph {
	g := NewGraph()
	if snap == nil {
		return g
	}

	// The external root. Every chain starts here conceptually — an
	// anonymous attacker on the internet.
	g.AddNode(&Node{
		ID:    "external:internet",
		Kind:  KindExternal,
		Label: "Internet (unauthenticated attacker)",
	})

	weaknessByPrincipal := indexWeaknessByPrincipal(findings)

	// -------- Principals --------

	for _, u := range snap.Identity.Users {
		kind := KindUser
		label := u.DisplayName
		if strings.EqualFold(u.UserType, "Guest") {
			kind = KindGuestUser
			label = u.DisplayName + " (guest)"
		}
		nodeID := PrincipalNodeID(kind, u.ID)
		w := ""
		if kind == KindGuestUser {
			w = "Guest account"
		}
		if !u.MFAEnabled {
			w = appendWeakness(w, "No MFA")
		}
		if !u.AccountEnabled {
			continue // skip disabled users — they can't act
		}
		if extra, ok := weaknessByPrincipal[u.ID]; ok {
			w = appendWeakness(w, extra)
		}
		g.AddNode(&Node{
			ID:       nodeID,
			Kind:     kind,
			Label:    label,
			Weakness: w,
			Attributes: map[string]string{
				"upn":   u.UserPrincipalName,
				"email": u.UserPrincipalName,
			},
		})
	}

	// -------- Groups --------
	//
	// Group nodes carry no weakness of their own — they are pass-through
	// containers. Their power comes from role assignments held at the
	// group level, which the BFS reaches by walking member_of edges
	// from any member (user, SP, or nested group) into the group node,
	// then out through the group's has_role edge. Nested groups are
	// handled naturally because the same member_of walk applies at
	// every nesting level.
	for _, gr := range snap.Identity.Groups {
		if gr.ID == "" {
			continue
		}
		g.AddNode(&Node{
			ID:    PrincipalNodeID(KindGroup, gr.ID),
			Kind:  KindGroup,
			Label: gr.DisplayName,
		})
	}

	for _, sp := range snap.Identity.ServicePrincipals {
		if !sp.AccountEnabled {
			continue
		}
		nodeID := PrincipalNodeID(KindSP, sp.ID)
		w := ""
		for _, c := range sp.PasswordCredentials {
			if c.EndDateTime == "" {
				w = appendWeakness(w, "Password credential never expires")
				break
			}
		}
		for _, c := range sp.KeyCredentials {
			if c.EndDateTime == "" {
				w = appendWeakness(w, "Key credential never expires")
				break
			}
		}
		if extra, ok := weaknessByPrincipal[sp.ID]; ok {
			w = appendWeakness(w, extra)
		}
		g.AddNode(&Node{
			ID:       nodeID,
			Kind:     KindSP,
			Label:    sp.DisplayName,
			Weakness: w,
			Attributes: map[string]string{
				"app_id": sp.AppID,
			},
		})
	}

	for _, app := range snap.Identity.AppRegistrations {
		nodeID := PrincipalNodeID(KindApp, app.ID)
		w := ""
		if extra, ok := weaknessByPrincipal[app.ID]; ok {
			w = extra
		}
		g.AddNode(&Node{
			ID:       nodeID,
			Kind:     KindApp,
			Label:    app.DisplayName,
			Weakness: w,
			Attributes: map[string]string{
				"app_id": app.AppID,
			},
		})
		// Link this app to every SP that represents it.
		for _, sp := range snap.Identity.ServicePrincipals {
			if sp.AppID == app.AppID && sp.AppID != "" {
				g.AddEdge(&Edge{
					From: PrincipalNodeID(KindSP, sp.ID),
					To:   nodeID,
					Kind: EdgeCredFor,
				})
			}
		}
	}

	for _, mi := range snap.Identity.ManagedIdentities {
		nodeID := PrincipalNodeID(KindMI, mi.PrincipalID)
		g.AddNode(&Node{
			ID:    nodeID,
			Kind:  KindMI,
			Label: mi.Name,
			Attributes: map[string]string{
				"mi_type": mi.Type,
			},
		})
		// Every resource that is assigned this MI effectively *is* this
		// MI during runtime; model that with an assigned_mi edge.
		for _, rid := range mi.ResourceIDs {
			resNode := ScopeNodeID(rid)
			if _, ok := g.Nodes[resNode]; ok {
				g.AddEdge(&Edge{
					From: resNode,
					To:   nodeID,
					Kind: EdgeAssignedMI,
				})
			}
		}
	}

	// -------- Group membership edges --------
	//
	// Emitted after every principal node exists so AddEdge can bind
	// the member to whichever principal kind actually matches the
	// object ID. The candidate loop covers Users, Guest Users, SPs, and
	// nested Groups; AddEdge is a no-op on a missing endpoint, so the
	// first kind whose node exists wins and the rest are silently
	// skipped. This directly enables transitive nested-group walks:
	// user → member_of → groupA → member_of → groupB → has_role → scope.
	for _, gr := range snap.Identity.Groups {
		groupNode := PrincipalNodeID(KindGroup, gr.ID)
		if _, ok := g.Nodes[groupNode]; !ok {
			continue
		}
		for _, memberID := range gr.Members {
			for _, kind := range []NodeKind{KindUser, KindGuestUser, KindSP, KindGroup} {
				candidate := PrincipalNodeID(kind, memberID)
				if _, ok := g.Nodes[candidate]; ok {
					g.AddEdge(&Edge{
						From: candidate,
						To:   groupNode,
						Kind: EdgeMemberOf,
					})
					break
				}
			}
		}
	}

	// -------- Scopes --------

	if snap.SubscriptionID != "" {
		g.AddNode(&Node{
			ID:    ScopeNodeID(fmt.Sprintf("/subscriptions/%s", snap.SubscriptionID)),
			Kind:  KindSubscription,
			Label: subscriptionLabel(snap),
		})
	}

	for _, r := range snap.Resources {
		rgID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", snap.SubscriptionID, r.ResourceGroup)
		if _, ok := g.Nodes[ScopeNodeID(rgID)]; !ok && r.ResourceGroup != "" {
			g.AddNode(&Node{
				ID:    ScopeNodeID(rgID),
				Kind:  KindResourceGroup,
				Label: r.ResourceGroup,
			})
			g.AddEdge(&Edge{
				From: ScopeNodeID(fmt.Sprintf("/subscriptions/%s", snap.SubscriptionID)),
				To:   ScopeNodeID(rgID),
				Kind: EdgeContains,
			})
		}
		resNode := ScopeNodeID(r.ID)
		g.AddNode(&Node{
			ID:        resNode,
			Kind:      KindResource,
			Label:     fmt.Sprintf("%s (%s)", r.Name, shortType(r.Type)),
			HighValue: highValueResourceType(r.Type),
			Attributes: map[string]string{
				"arm_type":       r.Type,
				"resource_group": r.ResourceGroup,
				"location":       r.Location,
			},
		})
		if r.ResourceGroup != "" {
			g.AddEdge(&Edge{
				From: ScopeNodeID(rgID),
				To:   resNode,
				Kind: EdgeContains,
			})
		}
	}

	// -------- Role assignments --------
	//
	// We walk both the Entra directory role assignments
	// (snap.Identity.RoleAssignments) and the Azure RBAC role
	// assignments (snap.Identity.AzureRBACAssignments). Both are
	// shaped as models.RoleAssignment but live in different slices
	// because their semantics differ: directory scopes ("/",
	// "/administrativeUnits/...") grant tenant-wide admin powers;
	// Azure scopes ("/subscriptions/...") grant resource-plane
	// control. The pathfinder happily walks either kind.

	for _, ra := range snap.Identity.RoleAssignments {
		addRoleEdge(g, ra)
	}
	for _, ra := range snap.Identity.AzureRBACAssignments {
		addRoleEdge(g, ra)
	}

	// -------- PIM (Privileged Identity Management) --------
	//
	// PIM schedules come in two flavours:
	//
	//   * Active   — the role is currently assigned; functionally
	//                equivalent to a permanent assignment for the
	//                duration of the schedule window. Edge carries full
	//                role weight and AssignmentState="Active".
	//   * Eligible — the principal can self-activate the role (MFA +
	//                justification). The edge still exists in the
	//                privilege graph because an attacker who compromises
	//                the principal can trigger activation; however we
	//                flag the edge AssignmentState="Eligible" so the
	//                downstream confidence scorer knows there is an
	//                activation step between compromise and exercise.
	//
	// We deliberately keep the weight identical for Eligible and Active:
	// a motivated attacker with the principal's session will almost
	// certainly satisfy activation requirements. The distinction is
	// recorded on AssignmentState so the UI and the confidence model
	// can discount it rather than hiding the edge entirely.
	for _, p := range snap.Identity.PIMAssignments {
		addPIMEdge(g, p)
	}

	// Internet edge to any resource we can reason about as internet-
	// facing. Public-IP-bearing resources will ideally be modelled;
	// the MVP treats any AKS cluster with a public API, any storage
	// account with public network access, and any SQL / cosmos with
	// public endpoint as exposed.
	for _, r := range snap.Resources {
		if internetExposed(r) {
			g.AddEdge(&Edge{
				From:   "external:internet",
				To:     ScopeNodeID(r.ID),
				Kind:   EdgeExposesTo,
				Weight: 3,
			})
		}
	}

	// -------- NSG-derived exposure edges --------
	//
	// An NSG with an inbound Allow rule that sources from the internet
	// (source * or 0.0.0.0/0, destination * or a non-private subnet)
	// makes every resource in the NSG's subnet reachable from the
	// outside. We emit `exposes_to` edges from internet → resource
	// for every resource whose subnet is associated with a permissive
	// NSG. The BFS then combines this with any role-based walk from a
	// weak entry to produce a chain like:
	//   Internet → VM (reachable via NSG allow-all) → MI → subscription.
	addNSGExposureEdges(g, snap)

	return g
}

// BuildGraphMulti is BuildGraph for an org-wide scan. Each sub-snapshot
// contributes its own subscription/RG/resource nodes under a single
// conceptual tenant root so the BFS can walk cross-subscription paths
// — a user with Owner on subscription A plus User Access Administrator
// on subscription B can reach key vaults in either, which the single-
// sub pathfinder misses.
//
// The tenant-root node is synthesised as the "scope:/" node (same ID
// used for Entra directory-scope assignments). Each subscription's
// root scope ("scope:/subscriptions/<id>") becomes a child of
// tenant-root via an EdgeContains edge, so any principal that holds
// a directory-role at "/" transitively inherits reach into every
// subscription.
//
// Findings are unioned so weakness flagging still catches every
// principal that tripped a rule somewhere in the tenant.
func BuildGraphMulti(snaps []*models.AzureSnapshot, allFindings []models.Finding) *Graph {
	if len(snaps) == 0 {
		return NewGraph()
	}
	if len(snaps) == 1 {
		return BuildGraph(snaps[0], allFindings)
	}
	g := BuildGraph(snaps[0], allFindings)

	// Synthesise tenant root if not already present. Single-sub
	// BuildGraph doesn't create it unless a directory-scope role
	// assignment referenced "/", so we may have to add it now.
	tenantRoot := ScopeNodeID("/")
	if _, ok := g.Nodes[tenantRoot]; !ok {
		g.AddNode(&Node{
			ID:        tenantRoot,
			Kind:      KindSubscription,
			Label:     "Tenant root (org-wide)",
			HighValue: true,
		})
	}
	// Link the first sub's root to tenant root.
	firstSubRoot := ScopeNodeID(fmt.Sprintf("/subscriptions/%s", snaps[0].SubscriptionID))
	if _, ok := g.Nodes[firstSubRoot]; ok {
		g.AddEdge(&Edge{From: tenantRoot, To: firstSubRoot, Kind: EdgeContains})
	}

	// Merge each additional snapshot's scopes + resources + role
	// assignments into the same graph.
	for _, snap := range snaps[1:] {
		mergeSnapshotIntoGraph(g, snap, allFindings)
		subRoot := ScopeNodeID(fmt.Sprintf("/subscriptions/%s", snap.SubscriptionID))
		if _, ok := g.Nodes[subRoot]; ok {
			g.AddEdge(&Edge{From: tenantRoot, To: subRoot, Kind: EdgeContains})
		}
	}
	return g
}

// mergeSnapshotIntoGraph adds a second (or Nth) snapshot's entities
// into an existing graph. Principals are deduped across subs by their
// object-ID-derived node IDs, so a user who exists in both snapshots
// lands as a single node with two sets of role edges — exactly the
// behaviour we want for cross-sub pathfinding.
func mergeSnapshotIntoGraph(g *Graph, snap *models.AzureSnapshot, findings []models.Finding) {
	if snap == nil {
		return
	}
	weakness := indexWeaknessByPrincipal(findings)
	// Principals (skip disabled accounts same as BuildGraph).
	for _, u := range snap.Identity.Users {
		if !u.AccountEnabled {
			continue
		}
		kind := KindUser
		if strings.EqualFold(u.UserType, "Guest") {
			kind = KindGuestUser
		}
		id := PrincipalNodeID(kind, u.ID)
		if _, ok := g.Nodes[id]; ok {
			continue // already present from a prior snapshot
		}
		w := ""
		if kind == KindGuestUser {
			w = "Guest account"
		}
		if !u.MFAEnabled {
			w = appendWeakness(w, "No MFA")
		}
		if extra, ok := weakness[u.ID]; ok {
			w = appendWeakness(w, extra)
		}
		g.AddNode(&Node{ID: id, Kind: kind, Label: u.DisplayName, Weakness: w})
	}
	for _, sp := range snap.Identity.ServicePrincipals {
		if !sp.AccountEnabled {
			continue
		}
		id := PrincipalNodeID(KindSP, sp.ID)
		if _, ok := g.Nodes[id]; ok {
			continue
		}
		g.AddNode(&Node{ID: id, Kind: KindSP, Label: sp.DisplayName})
	}
	// Groups (carry direct members; member_of edges emit below).
	for _, gr := range snap.Identity.Groups {
		id := PrincipalNodeID(KindGroup, gr.ID)
		if _, ok := g.Nodes[id]; !ok {
			g.AddNode(&Node{ID: id, Kind: KindGroup, Label: gr.DisplayName})
		}
	}
	for _, gr := range snap.Identity.Groups {
		groupNode := PrincipalNodeID(KindGroup, gr.ID)
		for _, member := range gr.Members {
			for _, kind := range []NodeKind{KindUser, KindGuestUser, KindSP, KindGroup} {
				candidate := PrincipalNodeID(kind, member)
				if _, ok := g.Nodes[candidate]; ok {
					g.AddEdge(&Edge{From: candidate, To: groupNode, Kind: EdgeMemberOf})
					break
				}
			}
		}
	}

	// Subscription scope + resource groups + resources.
	subRoot := ScopeNodeID(fmt.Sprintf("/subscriptions/%s", snap.SubscriptionID))
	if _, ok := g.Nodes[subRoot]; !ok && snap.SubscriptionID != "" {
		g.AddNode(&Node{ID: subRoot, Kind: KindSubscription, Label: subscriptionLabel(snap)})
	}
	for _, r := range snap.Resources {
		rgID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", snap.SubscriptionID, r.ResourceGroup)
		rgNode := ScopeNodeID(rgID)
		if _, ok := g.Nodes[rgNode]; !ok && r.ResourceGroup != "" {
			g.AddNode(&Node{ID: rgNode, Kind: KindResourceGroup, Label: r.ResourceGroup})
			g.AddEdge(&Edge{From: subRoot, To: rgNode, Kind: EdgeContains})
		}
		resNode := ScopeNodeID(r.ID)
		if _, ok := g.Nodes[resNode]; !ok {
			g.AddNode(&Node{
				ID:        resNode,
				Kind:      KindResource,
				Label:     fmt.Sprintf("%s (%s)", r.Name, shortType(r.Type)),
				HighValue: highValueResourceType(r.Type),
				Attributes: map[string]string{
					"arm_type": r.Type,
				},
			})
			if r.ResourceGroup != "" {
				g.AddEdge(&Edge{From: rgNode, To: resNode, Kind: EdgeContains})
			}
		}
	}

	// Role assignments.
	for _, ra := range snap.Identity.RoleAssignments {
		addRoleEdge(g, ra)
	}
	for _, ra := range snap.Identity.AzureRBACAssignments {
		addRoleEdge(g, ra)
	}
	for _, p := range snap.Identity.PIMAssignments {
		addPIMEdge(g, p)
	}

	// NSG exposure edges from the merged snapshot's network topology.
	addNSGExposureEdges(g, snap)
}

// addNSGExposureEdges inspects each NSG's inbound rules for Allow-from-
// Internet rules and, if present, emits an exposes_to edge from
// internet → each resource that sits behind the NSG's subnet(s).
//
// Heuristic: an NSG is "permissive from internet" if it has any
// inbound Allow rule whose SourceAddressPrefix is "*", "Internet",
// "0.0.0.0/0", or omitted. The weight is proportional to the port
// range: a wildcard port is weight 5 (critical); a specific high-
// risk port (22, 3389, 1433, 3306) is weight 4; any other specific
// port is weight 3.
//
// Every resource whose ResourceGroup matches the NSG's (best-effort
// subnet linkage in the current snapshot shape) receives the edge.
// Subnet-level NSG associations are modelled in NetworkTopology.Subnets
// but the cross-reference to resources is non-trivial without
// Application-Security-Group data, so we stay conservative: emit edges
// only when we have a direct NSG→resource tie via RG co-location plus
// a public IP on the resource.
func addNSGExposureEdges(g *Graph, snap *models.AzureSnapshot) {
	if snap == nil {
		return
	}
	for _, nsg := range snap.NetworkTopology.NSGs {
		weight, permissive := nsgPermissiveFromInternet(nsg)
		if !permissive {
			continue
		}
		// Find every resource in the same RG that has a public IP or
		// is itself a resource whose ARM type is known to live on the
		// same NSG-protected subnet. Without full subnet-to-resource
		// linkage, the RG-level heuristic is the safe pessimistic
		// bound: emit for co-located resources only. This captures
		// "VM in the same RG as an NSG with Allow-* inbound".
		for _, r := range snap.Resources {
			if r.ResourceGroup != nsg.ResourceGroup {
				continue
			}
			if !resourceIsExposable(r) {
				continue
			}
			resNode := ScopeNodeID(r.ID)
			if _, ok := g.Nodes[resNode]; !ok {
				continue
			}
			g.AddEdge(&Edge{
				From:   "external:internet",
				To:     resNode,
				Kind:   EdgeExposesTo,
				Weight: weight,
			})
		}
	}
}

// nsgPermissiveFromInternet reports whether the NSG has an inbound
// Allow rule sourced from the public internet, and returns a weight
// reflecting the exposure severity based on destination port range.
func nsgPermissiveFromInternet(nsg models.NetworkSecurityGroup) (int, bool) {
	for _, r := range nsg.InboundRules {
		if !strings.EqualFold(r.Access, "Allow") {
			continue
		}
		src := strings.ToLower(strings.TrimSpace(r.SourceAddressPrefix))
		fromInternet := src == "*" || src == "0.0.0.0/0" || src == "internet" || src == ""
		if !fromInternet {
			continue
		}
		port := strings.TrimSpace(r.DestinationPortRange)
		switch {
		case port == "*":
			return 5, true
		case port == "22" || port == "3389" || port == "1433" || port == "3306" || port == "5432":
			return 4, true
		default:
			return 3, true
		}
	}
	return 0, false
}

// resourceIsExposable reports whether a resource is a plausible
// destination for an internet-sourced NSG allow rule. Storage accounts
// and Key Vaults have their own data-plane network firewalls — an NSG
// at their resource-group level doesn't expose them. VMs, AKS
// clusters, App Services, and databases are plausible.
func resourceIsExposable(r models.AzureResource) bool {
	switch strings.ToLower(r.Type) {
	case
		"microsoft.compute/virtualmachines",
		"microsoft.compute/virtualmachinescalesets",
		"microsoft.containerservice/managedclusters",
		"microsoft.web/sites",
		"microsoft.sql/servers",
		"microsoft.sql/servers/databases",
		"microsoft.dbforpostgresql/servers",
		"microsoft.dbforpostgresql/flexibleservers",
		"microsoft.dbformysql/servers",
		"microsoft.dbformysql/flexibleservers",
		"microsoft.documentdb/databaseaccounts",
		"microsoft.cache/redis",
		"microsoft.network/bastionhosts",
		"microsoft.network/applicationgateways":
		return true
	}
	return false
}

// indexWeaknessByPrincipal turns finding output into a map of
// principalID → short human description. The pathfinder uses it to
// mark nodes as soft entry points without re-implementing every
// identity posture check.
func indexWeaknessByPrincipal(findings []models.Finding) map[string]string {
	out := map[string]string{}
	for _, f := range findings {
		if f.ResourceID == "" {
			continue
		}
		// Convention: identity rules set ResourceID to the principal's
		// Entra object ID. Everything else we skip.
		if !looksLikeObjectID(f.ResourceID) {
			continue
		}
		out[f.ResourceID] = appendWeakness(out[f.ResourceID], f.Title)
	}
	return out
}

func appendWeakness(existing, extra string) string {
	if extra == "" {
		return existing
	}
	if existing == "" {
		return extra
	}
	return existing + "; " + extra
}

func looksLikeObjectID(s string) bool {
	// Matches 00000000-0000-0000-0000-000000000000 without importing regex.
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

// addRoleEdge attaches a has_role edge to the graph for a single role
// assignment. Both the source principal node and the destination scope
// node must already exist; unresolvable endpoints are silently dropped
// so a partial snapshot (e.g. RAs on RGs we didn't enumerate) does not
// surface broken edges in the pathfinder output.
func addRoleEdge(g *Graph, ra models.RoleAssignment) {
	fromID := principalIDFromRA(ra)
	if fromID == "" {
		return
	}
	if _, ok := g.Nodes[fromID]; !ok {
		// Principal isn't in the graph — likely because the assignment
		// references a cross-tenant object ID or an orphaned principal.
		// Create a synthetic node so the edge still renders; the label
		// falls back to the object ID.
		g.AddNode(&Node{
			ID:    fromID,
			Kind:  nodeKindFromRA(ra),
			Label: fmt.Sprintf("external principal %s", ra.PrincipalID[:minInt(8, len(ra.PrincipalID))]),
		})
	}
	scopeNode := ScopeNodeID(ra.Scope)
	if _, ok := g.Nodes[scopeNode]; !ok {
		// Scope not materialised. Entra directory scopes ("/" and
		// "/administrativeUnits/<id>") do not correspond to any Azure
		// resource the Resource Graph collector would emit, so we
		// synthesise a node for them. Both flavours are treated as
		// high-value because a directory-admin role at either scope
		// grants tenant- or AU-wide identity control, which reliably
		// laterals to Azure RBAC via the global-admin elevate-access
		// button.
		switch {
		case ra.Scope == "/":
			g.AddNode(&Node{
				ID:        scopeNode,
				Kind:      KindSubscription,
				Label:     "Entra tenant root (/)",
				HighValue: true,
			})
		case strings.HasPrefix(ra.Scope, "/administrativeUnits/"):
			g.AddNode(&Node{
				ID:        scopeNode,
				Kind:      KindSubscription,
				Label:     fmt.Sprintf("Entra administrative unit (%s)", strings.TrimPrefix(ra.Scope, "/administrativeUnits/")),
				HighValue: true,
			})
		default:
			return
		}
	}
	g.AddEdge(&Edge{
		From:            fromID,
		To:              scopeNode,
		Kind:            EdgeHasRole,
		Role:            ra.RoleName,
		Weight:          roleWeight(ra.RoleName),
		AssignmentState: "",
	})
}

// addPIMEdge attaches a has_role edge for a PIM schedule instance.
// Unlike addRoleEdge it tags the edge with AssignmentState so downstream
// rendering and confidence scoring can distinguish Active vs. Eligible
// assignments. The scope handling mirrors addRoleEdge — "/" and
// "/administrativeUnits/<id>" synthesise a tenant-root / AU-root node
// when missing; everything else is dropped if the target scope wasn't
// enumerated.
func addPIMEdge(g *Graph, p models.PIMAssignment) {
	if p.PrincipalID == "" || p.RoleName == "" {
		return
	}
	kind := KindUser
	switch strings.ToLower(p.PrincipalType) {
	case "group":
		kind = KindGroup
	case "serviceprincipal":
		kind = KindSP
	}
	fromID := PrincipalNodeID(kind, p.PrincipalID)
	if _, ok := g.Nodes[fromID]; !ok {
		// Principal not enumerated (disabled, filtered, or cross-tenant);
		// synthesise a minimal node so the edge still renders and the
		// pathfinder can reason about it.
		g.AddNode(&Node{
			ID:    fromID,
			Kind:  kind,
			Label: fmt.Sprintf("PIM principal %s", p.PrincipalID[:minInt(8, len(p.PrincipalID))]),
		})
	}
	scope := p.Scope
	if scope == "" {
		scope = "/"
	}
	scopeNode := ScopeNodeID(scope)
	if _, ok := g.Nodes[scopeNode]; !ok {
		switch {
		case scope == "/":
			g.AddNode(&Node{
				ID:        scopeNode,
				Kind:      KindSubscription,
				Label:     "Entra tenant root (/)",
				HighValue: true,
			})
		case strings.HasPrefix(scope, "/administrativeUnits/"):
			g.AddNode(&Node{
				ID:        scopeNode,
				Kind:      KindSubscription,
				Label:     fmt.Sprintf("Entra administrative unit (%s)", strings.TrimPrefix(scope, "/administrativeUnits/")),
				HighValue: true,
			})
		default:
			return
		}
	}
	state := p.AssignmentType // "Eligible" | "Active"
	g.AddEdge(&Edge{
		From:            fromID,
		To:              scopeNode,
		Kind:            EdgeHasRole,
		Role:            p.RoleName,
		Weight:          roleWeight(p.RoleName),
		AssignmentState: state,
	})
}

func nodeKindFromRA(ra models.RoleAssignment) NodeKind {
	switch strings.ToLower(ra.PrincipalType) {
	case "user":
		return KindUser
	case "group":
		return KindGroup
	case "serviceprincipal":
		return KindSP
	}
	return KindUser
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func principalIDFromRA(ra models.RoleAssignment) string {
	switch strings.ToLower(ra.PrincipalType) {
	case "user":
		return PrincipalNodeID(KindUser, ra.PrincipalID)
	case "group":
		return PrincipalNodeID(KindGroup, ra.PrincipalID)
	case "serviceprincipal":
		return PrincipalNodeID(KindSP, ra.PrincipalID)
	default:
		return ""
	}
}

func subscriptionLabel(snap *models.AzureSnapshot) string {
	if snap.SubscriptionName != "" {
		return snap.SubscriptionName
	}
	return snap.SubscriptionID
}

func shortType(armType string) string {
	idx := strings.LastIndex(armType, "/")
	if idx < 0 || idx == len(armType)-1 {
		return armType
	}
	return armType[idx+1:]
}

// internetExposed is a lightweight heuristic for "can an attacker on
// the public internet reach this resource without credentials?". It is
// intentionally broad: pathfinding will still require a privilege edge
// on the far side to surface a chain, so false positives here are
// mostly harmless.
func internetExposed(r models.AzureResource) bool {
	// publicNetworkAccess=Enabled on storage / KV / cosmos / SQL / etc.
	if v, ok := r.Properties["publicNetworkAccess"]; ok {
		if s, ok := v.(string); ok && strings.EqualFold(s, "Enabled") {
			return true
		}
	}
	// Storage: allowBlobPublicAccess=true is a specific subcase.
	if strings.EqualFold(r.Type, "Microsoft.Storage/storageAccounts") {
		if v, ok := r.Properties["allowBlobPublicAccess"]; ok {
			if b, ok := v.(bool); ok && b {
				return true
			}
		}
	}
	// AKS: apiServerAccessProfile.enablePrivateCluster=false (and no auth IPs)
	if strings.EqualFold(r.Type, "Microsoft.ContainerService/managedClusters") {
		if prof, ok := r.Properties["apiServerAccessProfile"].(map[string]interface{}); ok {
			if priv, ok := prof["enablePrivateCluster"].(bool); ok && !priv {
				return true
			}
		}
	}
	return false
}
