package pathfinder

import (
	"strings"
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

// sampleSnapshot builds a tiny but realistic snapshot: one guest user,
// one subscription containing a key vault, and a Contributor role
// assignment from the guest directly to the subscription. A correctly
// working pathfinder must return one chain: guest → subscription → KV.
func sampleSnapshot() *models.AzureSnapshot {
	snap := &models.AzureSnapshot{
		SubscriptionID:   "11111111-1111-1111-1111-111111111111",
		SubscriptionName: "prod",
		TenantID:         "22222222-2222-2222-2222-222222222222",
		Identity: models.IdentitySnapshot{
			Users: []models.AADUser{
				{
					ID:                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
					DisplayName:       "external partner",
					UserPrincipalName: "partner@external.com",
					AccountEnabled:    true,
					UserType:          "Guest",
					MFAEnabled:        false,
				},
			},
			RoleAssignments: []models.RoleAssignment{
				{
					ID:               "ra1",
					RoleDefinitionID: "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Authorization/roleDefinitions/contributor",
					RoleName:         "Contributor",
					PrincipalID:      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
					PrincipalType:    "User",
					Scope:            "/subscriptions/11111111-1111-1111-1111-111111111111",
				},
			},
		},
		Resources: []models.AzureResource{
			{
				ID:            "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv-prod",
				Name:          "kv-prod",
				Type:          "Microsoft.KeyVault/vaults",
				Location:      "eastus",
				ResourceGroup: "rg1",
				Properties:    map[string]interface{}{},
			},
		},
	}
	return snap
}

func TestBuildGraph_NodeCounts(t *testing.T) {
	g := BuildGraph(sampleSnapshot(), nil)
	// Expect: 1 external + 1 guest user + 1 sub + 1 RG + 1 resource = 5.
	if len(g.Nodes) != 5 {
		t.Fatalf("expected 5 nodes, got %d: %s", len(g.Nodes), g.Stats())
	}
	var edgeCount int
	for _, es := range g.OutEdges {
		edgeCount += len(es)
	}
	if edgeCount == 0 {
		t.Errorf("expected some edges, got %d", edgeCount)
	}
}

func TestDiscover_FindsGuestContributorPath(t *testing.T) {
	snap := sampleSnapshot()
	opts := FindOptions{MaxHops: 6, MinWeight: 5, TopK: 10}
	chains := DiscoverChainsWithOptions(snap, nil, opts)
	if len(chains) == 0 {
		t.Fatal("expected at least one discovered chain from guest with Contributor")
	}
	c := chains[0]
	if !strings.HasPrefix(c.ID, "DISC-") {
		t.Errorf("discovered chain IDs must be DISC-*, got %q", c.ID)
	}
	if c.Severity == "" {
		t.Error("severity not populated")
	}
	if len(c.Steps) == 0 {
		t.Error("chain has no steps")
	}
}

func TestDiscover_HonoursMinWeight(t *testing.T) {
	snap := sampleSnapshot()
	// Override the sole role assignment with Reader (weight 1). With
	// MinWeight=5 the pathfinder should emit zero chains because no
	// walk is privileged enough.
	snap.Identity.RoleAssignments[0].RoleName = "Reader"
	chains := DiscoverChainsWithOptions(snap, nil, FindOptions{MaxHops: 6, MinWeight: 5, TopK: 10})
	if len(chains) != 0 {
		t.Errorf("Reader-only walk should not meet min weight, got %d chains", len(chains))
	}
}

func TestRoleWeight_KnownAndUnknown(t *testing.T) {
	if roleWeight("Owner") != 10 {
		t.Error("Owner weight drifted")
	}
	if roleWeight("Contributor") != 8 {
		t.Error("Contributor weight drifted")
	}
	if roleWeight("Reader") != 1 {
		t.Error("Reader weight drifted")
	}
	if roleWeight("Made Up Role") != 2 {
		t.Error("unknown roles should default to 2")
	}
}

func TestDedupe_CollapsesSimilarPaths(t *testing.T) {
	// Two paths, same source, destination, and first-role: dedupe
	// should keep only the higher-weight one.
	n1 := &Node{ID: "a", Kind: KindUser, Label: "A"}
	n2 := &Node{ID: "b", Kind: KindSubscription, Label: "B"}
	paths := []Path{
		{Nodes: []*Node{n1, n2}, Edges: []*Edge{{From: "a", To: "b", Kind: EdgeHasRole, Role: "Owner", Weight: 10}}, TotalWeight: 10},
		{Nodes: []*Node{n1, n2}, Edges: []*Edge{{From: "a", To: "b", Kind: EdgeHasRole, Role: "Owner", Weight: 9}}, TotalWeight: 9},
	}
	out := dedupe(paths)
	if len(out) != 1 {
		t.Fatalf("dedupe should keep one, got %d", len(out))
	}
	if out[0].TotalWeight != 10 {
		t.Errorf("higher weight not preserved: %d", out[0].TotalWeight)
	}
}

func TestLooksLikeObjectID(t *testing.T) {
	if !looksLikeObjectID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") {
		t.Error("valid GUID rejected")
	}
	if looksLikeObjectID("not a guid") {
		t.Error("non-GUID accepted")
	}
	if looksLikeObjectID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa") { // too short
		t.Error("short GUID accepted")
	}
}

func TestSeverityForPath_GuestWithUAAIsCritical(t *testing.T) {
	guest := &Node{ID: "user:g1", Kind: KindGuestUser, Label: "guest"}
	target := &Node{ID: "scope:/", Kind: KindSubscription, HighValue: true}
	p := Path{
		Nodes: []*Node{guest, target},
		Edges: []*Edge{{From: "user:g1", To: "scope:/", Kind: EdgeHasRole, Role: "User Access Administrator", Weight: 10}},
		TotalWeight: 10,
	}
	if got := severityForPath(p); got != "CRITICAL" {
		t.Errorf("guest with UAA should be CRITICAL, got %s", got)
	}
	if got := likelihoodForPath(p); got != "High" {
		t.Errorf("guest entry should carry High likelihood, got %s", got)
	}
}

func TestSeverityForPath_InternalUserWithOwnerIsHigh(t *testing.T) {
	user := &Node{ID: "user:u1", Kind: KindUser, Label: "user", Weakness: "No MFA"}
	target := &Node{ID: "scope:/sub", Kind: KindSubscription, HighValue: true}
	p := Path{
		Nodes: []*Node{user, target},
		Edges: []*Edge{{From: "user:u1", To: "scope:/sub", Kind: EdgeHasRole, Role: "Owner", Weight: 10}},
		TotalWeight: 10,
	}
	if got := severityForPath(p); got != "HIGH" {
		t.Errorf("internal user with Owner should be HIGH, got %s", got)
	}
}

func TestSeverityForPath_ContributorIsMedium(t *testing.T) {
	user := &Node{ID: "user:u1", Kind: KindUser, Label: "user", Weakness: "No MFA"}
	target := &Node{ID: "scope:/rg", Kind: KindResourceGroup, HighValue: true}
	p := Path{
		Nodes: []*Node{user, target},
		Edges: []*Edge{{From: "user:u1", To: "scope:/rg", Kind: EdgeHasRole, Role: "Contributor", Weight: 8}},
		TotalWeight: 8,
	}
	if got := severityForPath(p); got != "MEDIUM" {
		t.Errorf("Contributor-only walk should be MEDIUM, got %s", got)
	}
}

// TestBuildGraph_UsesAzureRBAC verifies that role assignments placed
// on the new AzureRBACAssignments slice produce has_role edges in the
// graph — regression test for the case where only Entra directory
// role assignments were consumed, causing the pathfinder to miss every
// Azure RBAC-derived privilege path.
func TestBuildGraph_UsesAzureRBAC(t *testing.T) {
	snap := sampleSnapshot()
	// Move the role assignment from directory to Azure RBAC.
	snap.Identity.AzureRBACAssignments = snap.Identity.RoleAssignments
	snap.Identity.RoleAssignments = nil
	chains := DiscoverChainsWithOptions(snap, nil, FindOptions{MaxHops: 6, MinWeight: 5, TopK: 10})
	if len(chains) == 0 {
		t.Fatal("graph builder must consume AzureRBACAssignments, found 0 chains")
	}
}

// TestAddRoleEdge_CreatesTenantRootForDirectoryScope verifies that a
// directory-scoped assignment (Scope="/") does not get dropped when
// the tenant root node isn't pre-created by the resource loop; the
// builder synthesises a tenant root node so Entra admin-role walks
// can still be discovered.
func TestAddRoleEdge_CreatesTenantRootForDirectoryScope(t *testing.T) {
	snap := &models.AzureSnapshot{
		SubscriptionID: "sub1",
		Identity: models.IdentitySnapshot{
			Users: []models.AADUser{{
				ID: "11111111-1111-1111-1111-111111111111",
				DisplayName: "admin", AccountEnabled: true, MFAEnabled: false,
			}},
			RoleAssignments: []models.RoleAssignment{{
				PrincipalID:   "11111111-1111-1111-1111-111111111111",
				PrincipalType: "User",
				RoleName:      "Global Administrator",
				Scope:         "/",
			}},
		},
	}
	g := BuildGraph(snap, nil)
	tenantRoot := "scope:/"
	if _, ok := g.Nodes[tenantRoot]; !ok {
		t.Fatalf("tenant root node should be synthesised for directory-scope RA, graph: %s", g.Stats())
	}
	found := false
	for _, e := range g.OutEdges["user:11111111-1111-1111-1111-111111111111"] {
		if e.To == tenantRoot && e.Kind == EdgeHasRole {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected has_role edge from admin user to tenant root")
	}
}

// TestBuildGraph_NestedGroupMembership verifies that a user nested two
// groups deep inherits the outer group's role assignment. This is the
// core P2 capability — without transitive walks, user U never shows up
// as having Owner on the subscription even though he is a member of
// group A which is a member of group B which holds Owner.
func TestBuildGraph_NestedGroupMembership(t *testing.T) {
	snap := &models.AzureSnapshot{
		SubscriptionID: "11111111-1111-1111-1111-111111111111",
		Identity: models.IdentitySnapshot{
			Users: []models.AADUser{{
				ID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
				DisplayName: "inner user", AccountEnabled: true, MFAEnabled: false,
			}},
			Groups: []models.AADGroup{
				{
					ID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
					DisplayName: "inner group",
					Members:     []string{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
				},
				{
					ID: "cccccccc-cccc-cccc-cccc-cccccccccccc",
					DisplayName: "outer group",
					Members:     []string{"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
				},
			},
			AzureRBACAssignments: []models.RoleAssignment{{
				PrincipalID:   "cccccccc-cccc-cccc-cccc-cccccccccccc",
				PrincipalType: "Group",
				RoleName:      "Owner",
				Scope:         "/subscriptions/11111111-1111-1111-1111-111111111111",
			}},
		},
	}
	// Need a subscription node so addRoleEdge binds. The builder
	// creates one when snap.SubscriptionID is populated.
	chains := DiscoverChainsWithOptions(snap, []models.Finding{{
		ResourceID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Title:      "No MFA",
	}}, FindOptions{MaxHops: 6, MinWeight: 8, TopK: 10})
	if len(chains) == 0 {
		t.Fatal("nested group walk should produce a discovered chain (user → innerGroup → outerGroup → Owner → subscription)")
	}
	found := false
	for _, c := range chains {
		if strings.Contains(c.Narrative, "inner group") && strings.Contains(c.Narrative, "outer group") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a chain traversing both inner and outer groups; got titles: %+v", chainTitles(chains))
	}
}

// TestBuildGraph_EntraDirectoryRoleGetsTenantTakeoverWeight verifies
// that Global Administrator at tenant scope produces a weight-10 edge
// (tenant takeover), not the default weight-2 unknown-role fallback.
func TestBuildGraph_EntraDirectoryRoleGetsTenantTakeoverWeight(t *testing.T) {
	snap := &models.AzureSnapshot{
		SubscriptionID: "sub1",
		Identity: models.IdentitySnapshot{
			Users: []models.AADUser{{
				ID: "11111111-1111-1111-1111-111111111111",
				DisplayName: "admin", AccountEnabled: true, MFAEnabled: false,
			}},
			RoleAssignments: []models.RoleAssignment{{
				PrincipalID:   "11111111-1111-1111-1111-111111111111",
				PrincipalType: "User",
				RoleName:      "Global Administrator",
				Scope:         "/",
			}},
		},
	}
	g := BuildGraph(snap, nil)
	edges := g.OutEdges["user:11111111-1111-1111-1111-111111111111"]
	if len(edges) == 0 {
		t.Fatal("admin user should have a has_role edge to tenant root")
	}
	found := false
	for _, e := range edges {
		if e.Role == "Global Administrator" && e.Weight == 10 {
			found = true
		}
	}
	if !found {
		t.Errorf("Global Administrator should have weight 10, got edges: %+v", edges)
	}
}

// TestAddPIMEdge_ActiveAndEligible verifies that both PIM Active and
// Eligible assignments produce has_role edges, each tagged with the
// correct AssignmentState. The two edges should carry identical weight
// so the BFS finds both paths — the confidence scorer is what
// distinguishes them downstream.
func TestAddPIMEdge_ActiveAndEligible(t *testing.T) {
	snap := &models.AzureSnapshot{
		SubscriptionID: "sub1",
		Identity: models.IdentitySnapshot{
			Users: []models.AADUser{
				{ID: "11111111-1111-1111-1111-111111111111", DisplayName: "active user", AccountEnabled: true},
				{ID: "22222222-2222-2222-2222-222222222222", DisplayName: "eligible user", AccountEnabled: true},
			},
			PIMAssignments: []models.PIMAssignment{
				{PrincipalID: "11111111-1111-1111-1111-111111111111", PrincipalType: "User", RoleName: "Privileged Role Administrator", AssignmentType: "Active", Scope: "/"},
				{PrincipalID: "22222222-2222-2222-2222-222222222222", PrincipalType: "User", RoleName: "Privileged Role Administrator", AssignmentType: "Eligible", Scope: "/"},
			},
		},
	}
	g := BuildGraph(snap, nil)

	var activeEdge, eligibleEdge *Edge
	for _, e := range g.OutEdges["user:11111111-1111-1111-1111-111111111111"] {
		if e.Role == "Privileged Role Administrator" {
			activeEdge = e
		}
	}
	for _, e := range g.OutEdges["user:22222222-2222-2222-2222-222222222222"] {
		if e.Role == "Privileged Role Administrator" {
			eligibleEdge = e
		}
	}
	if activeEdge == nil || activeEdge.AssignmentState != "Active" {
		t.Errorf("Active PIM edge missing or mis-tagged: %+v", activeEdge)
	}
	if eligibleEdge == nil || eligibleEdge.AssignmentState != "Eligible" {
		t.Errorf("Eligible PIM edge missing or mis-tagged: %+v", eligibleEdge)
	}
	if activeEdge != nil && eligibleEdge != nil && activeEdge.Weight != eligibleEdge.Weight {
		t.Errorf("Active and Eligible weights should match (the scorer distinguishes them), got %d vs %d", activeEdge.Weight, eligibleEdge.Weight)
	}
}

// TestConfidenceForPath_EligibleDowngrades verifies that a PIM-eligible
// walk lands in a strictly lower confidence bucket than an otherwise
// identical permanent walk. Eligible = activation step = less certain.
//
// Inputs chosen to straddle the High/Medium bucket boundary:
//   Permanent: 2 (weight=8) + 1 (3-edge) + 1 (weakness) = 4 → Medium (base)
//   Eligible:  same minus 1 = 3 → Medium still — so we pick a boundary
// case. The clearest demonstration is a single-edge walk:
//   Permanent: 2 (weight=8) + 2 (1-edge) + 1 (weakness) = 5 → High
//   Eligible:  4 → Medium
func TestConfidenceForPath_EligibleDowngrades(t *testing.T) {
	user := &Node{ID: "user:u1", Kind: KindUser, Label: "user", Weakness: "No MFA"}
	target := &Node{ID: "scope:/sub", Kind: KindSubscription, HighValue: true}
	permanent := Path{
		Nodes: []*Node{user, target},
		Edges: []*Edge{{From: "user:u1", To: "scope:/sub", Kind: EdgeHasRole, Role: "Contributor", Weight: 8}},
		TotalWeight: 8,
	}
	eligible := Path{
		Nodes: []*Node{user, target},
		Edges: []*Edge{{From: "user:u1", To: "scope:/sub", Kind: EdgeHasRole, Role: "Contributor", Weight: 8, AssignmentState: "Eligible"}},
		TotalWeight: 8,
	}
	permConf := confidenceForPath(permanent, false)
	eligConf := confidenceForPath(eligible, false)
	if permConf != "High" {
		t.Errorf("permanent Contributor walk with weak entry should be High, got %s", permConf)
	}
	if eligConf != "Medium" {
		t.Errorf("PIM-eligible version of same walk should drop to Medium, got %s", eligConf)
	}
}

func chainTitles(chains []models.AttackChain) []string {
	out := make([]string, 0, len(chains))
	for _, c := range chains {
		out = append(out, c.Title)
	}
	return out
}

func TestHighValueResourceType(t *testing.T) {
	if !highValueResourceType("microsoft.keyvault/vaults") {
		t.Error("Key Vault should be high-value")
	}
	if !highValueResourceType("Microsoft.Storage/storageAccounts") {
		t.Error("case-insensitive match failed")
	}
	if highValueResourceType("microsoft.web/sites") {
		t.Error("App Service should not be high-value by default")
	}
}
