package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/vatsayanvivek/argus/internal/models"
)

// graphBaseURL is the Microsoft Graph v1.0 endpoint used for every call in
// this file. We intentionally use raw REST rather than the msgraph-sdk-go
// module because the latter pulls in a very large transitive dependency tree
// we do not need.
const graphBaseURL = "https://graph.microsoft.com/v1.0"

// HighPrivilegeGraphPerms maps Microsoft Graph application permission IDs
// (the GUIDs inside an App Registration's requiredResourceAccess block, Type
// "Role") to their human-readable names. These are the permissions that, if
// granted to a compromised service principal, lead directly to tenant-wide
// takeover. ARGUS rules reference this set when scoring App Registration
// takeover chains (notably CHAIN-002).
//
// It is exported so policy packages can reuse the same mapping without
// duplicating the GUIDs.
var HighPrivilegeGraphPerms = map[string]string{
	"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
	"06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
	"1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
	"62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
	"741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
}

// graphClient wraps a minimal Graph HTTP client with a pre-acquired bearer
// token. A token acquired here is valid for roughly 1h; we intentionally
// don't refresh mid-collection because a single CollectAll invocation runs in
// well under that window.
//
// missingScopes records the human-readable Microsoft Graph permission
// names that the scanning identity did not have at scan time. It is
// populated from soft-failed (401/403) responses by the policy → scope
// mapping in graphScopeForEndpoint. The collector exposes it on the
// snapshot so the report can surface a prominent warning.
type graphClient struct {
	http          *http.Client
	token         string
	missingScopes map[string]bool
}

// graphScopeForEndpoint maps Graph URL prefixes to the Microsoft Graph
// application permission names that grant access to them. It is used
// to translate a soft-failed endpoint into a human-readable scope the
// user can ask their Global Admin to grant. Order matters — longer
// prefixes are checked first so /identityGovernance/accessReviews
// resolves before /identity.
var graphScopeForEndpoint = []struct {
	prefix string
	scope  string
}{
	{"/applications", "Application.Read.All"},
	{"/identityGovernance/accessReviews", "AccessReview.Read.All"},
	{"/identity/conditionalAccess", "Policy.Read.All"},
	{"/policies/authenticationMethodsPolicy", "Policy.Read.All"},
	{"/policies/crossTenantAccessPolicy", "Policy.Read.All"},
	{"/policies/authorizationPolicy", "Policy.Read.All"},
	{"/roleManagement/directory/roleEligibilitySchedule", "RoleManagement.Read.Directory"},
	{"/roleManagement/directory/roleAssignmentSchedule", "RoleManagement.Read.Directory"},
	{"/roleManagement/directory", "RoleManagement.Read.Directory"},
	{"/users", "Directory.Read.All"},
	{"/servicePrincipals", "Directory.Read.All"},
	{"/groups/", "GroupMember.Read.All"},
	{"/groups", "Directory.Read.All"},
	{"/auditLogs", "AuditLog.Read.All"},
	{"/reports", "Reports.Read.All"},
	{"/security", "SecurityEvents.Read.All"},
}

// recordMissingScope translates an endpoint that just returned 401/403
// into the corresponding Graph scope and records it on the client.
func (g *graphClient) recordMissingScope(endpoint string) {
	if g.missingScopes == nil {
		g.missingScopes = map[string]bool{}
	}
	for _, m := range graphScopeForEndpoint {
		if strings.HasPrefix(endpoint, m.prefix) {
			g.missingScopes[m.scope] = true
			return
		}
	}
	// Endpoint doesn't match any known prefix — record the raw path so
	// the operator at least sees something useful.
	g.missingScopes["(unknown scope: "+endpoint+")"] = true
}

// MissingScopes returns the sorted list of Graph scopes that were
// missing during collection. Empty when full Graph access was granted.
func (g *graphClient) MissingScopes() []string {
	if len(g.missingScopes) == 0 {
		return nil
	}
	out := make([]string, 0, len(g.missingScopes))
	for s := range g.missingScopes {
		out = append(out, s)
	}
	// Stable sort for deterministic reports.
	sortStrings(out)
	return out
}

// sortStrings is a tiny in-place sort to avoid pulling the sort package
// just for one usage.
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// newGraphClient authenticates against Microsoft Graph using the supplied
// credential and returns a ready-to-use client. A failure to acquire the
// token is a hard error — without a token every subsequent call would 401,
// so we surface it to the caller (who will record it on CollectionErrors).
func newGraphClient(ctx context.Context, cred azcore.TokenCredential) (*graphClient, error) {
	tk, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("acquire graph token: %w", err)
	}
	return &graphClient{
		http:  &http.Client{Timeout: 30 * time.Second},
		token: tk.Token,
	}, nil
}

// get performs a single GET against the Graph API and decodes the JSON body
// into `out`. It honors paging transparently — caller passes the relative
// path and receives all pages merged via getPaged instead of this. This
// single-shot variant is used only for the tenant settings endpoints that
// return a single object.
func (g *graphClient) get(ctx context.Context, rel string, out interface{}) (int, error) {
	fullURL := rel
	if !strings.HasPrefix(rel, "http") {
		fullURL = graphBaseURL + rel
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")

	resp, err := g.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("graph %s %s: %s", req.Method, rel, strings.TrimSpace(string(body)))
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode graph response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// getPaged fetches every page of a Graph collection and returns the combined
// `value` array. Graph uses an "@odata.nextLink" cursor which is a full URL.
// The function is soft on 403/404 — those are logged, the corresponding
// missing Graph scope is recorded on the client, and an empty slice is
// returned so a locked-down tenant still produces a usable snapshot.
func (g *graphClient) getPaged(ctx context.Context, rel string) ([]map[string]interface{}, error) {
	all := []map[string]interface{}{}
	next := rel
	pageCap := 50 // hard upper bound on pages to keep scans bounded
	for i := 0; next != "" && i < pageCap; i++ {
		var page struct {
			Value    []map[string]interface{} `json:"value"`
			NextLink string                   `json:"@odata.nextLink"`
		}
		status, err := g.get(ctx, next, &page)
		if err != nil {
			if status == http.StatusForbidden || status == http.StatusNotFound || status == http.StatusUnauthorized {
				log.Printf("[argus/azure] graph %s soft-failed (%d): %v", rel, status, err)
				if status == http.StatusForbidden || status == http.StatusUnauthorized {
					g.recordMissingScope(rel)
				}
				return all, nil
			}
			return all, err
		}
		all = append(all, page.Value...)
		next = page.NextLink
	}
	return all, nil
}

// collectIdentity fetches everything under the Azure AD "identity" umbrella.
// It returns a fully-populated IdentitySnapshot together with the list
// of Microsoft Graph scopes that were missing during collection (empty
// when full Graph access was granted). Individual sub-queries are
// wrapped — one 403 will not prevent the remainder from running.
func collectIdentity(
	ctx context.Context,
	cred azcore.TokenCredential,
	tenantID string,
) (models.IdentitySnapshot, []string, error) {
	snap := models.IdentitySnapshot{
		Users:             []models.AADUser{},
		Groups:            []models.AADGroup{},
		ServicePrincipals: []models.ServicePrincipal{},
		AppRegistrations:  []models.AppRegistration{},
		ManagedIdentities: []models.ManagedIdentity{},
		ConditionalAccess: []models.ConditionalAccessPolicy{},
		PIMAssignments:    []models.PIMAssignment{},
		RoleAssignments:   []models.RoleAssignment{},
		AccessReviews:     []models.AccessReview{},
	}

	gc, err := newGraphClient(ctx, cred)
	if err != nil {
		return snap, nil, err
	}

	// ---- Users ----
	users, uerr := gc.getPaged(ctx, "/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,signInActivity&$top=999")
	if uerr != nil {
		log.Printf("[argus/azure] identity users error: %v", uerr)
	}
	for _, u := range users {
		user := models.AADUser{
			ID:                jsonString(u, "id"),
			DisplayName:       jsonString(u, "displayName"),
			UserPrincipalName: jsonString(u, "userPrincipalName"),
			UserType:          jsonString(u, "userType"),
			AssignedRoles:     []string{},
		}
		if v, ok := u["accountEnabled"].(bool); ok {
			user.AccountEnabled = v
		}
		if v, ok := u["onPremisesSyncEnabled"].(bool); ok {
			user.OnPremisesSyncEnabled = v
		}
		if sia, ok := u["signInActivity"].(map[string]interface{}); ok {
			user.LastSignInDateTime = jsonString(sia, "lastSignInDateTime")
		}
		// MFA is not exposed on /users; reports come from the Reports API
		// under separate permissions. Default to false; the policy layer
		// treats unknowns conservatively.
		user.MFAEnabled = false
		snap.Users = append(snap.Users, user)
	}

	// ---- Groups (with direct members for transitive walk) ----
	//
	// Transitive group membership is the single most common way a user
	// ends up with a privilege they don't realise they have: user is in
	// group A, group A is nested inside group B, group B holds Owner on
	// a subscription. The pathfinder needs the full member graph to
	// discover those walks. We fetch direct members only (cheap) and let
	// the BFS traverse member_of edges transitively.
	groups, gerr := gc.getPaged(ctx, "/groups?$select=id,displayName,securityEnabled,mailEnabled&$top=999")
	if gerr != nil {
		log.Printf("[argus/azure] identity groups error: %v", gerr)
	}
	for _, g := range groups {
		grp := models.AADGroup{
			ID:          jsonString(g, "id"),
			DisplayName: jsonString(g, "displayName"),
			Members:     []string{},
		}
		if v, ok := g["securityEnabled"].(bool); ok {
			grp.SecurityEnabled = v
		}
		if v, ok := g["mailEnabled"].(bool); ok {
			grp.MailEnabled = v
		}
		if grp.ID != "" {
			// Fetch direct members. Using $select=id keeps the payload
			// small; we don't need display fields here because the
			// members are cross-referenced by object ID at graph-build
			// time.
			mems, merr := gc.getPaged(ctx, fmt.Sprintf("/groups/%s/members?$select=id&$top=999", grp.ID))
			if merr != nil {
				log.Printf("[argus/azure] group %s members error: %v", grp.ID, merr)
			}
			for _, m := range mems {
				if id := jsonString(m, "id"); id != "" {
					grp.Members = append(grp.Members, id)
				}
			}
		}
		snap.Groups = append(snap.Groups, grp)
	}

	// ---- Service Principals ----
	sps, serr := gc.getPaged(ctx, "/servicePrincipals?$select=id,displayName,appId,servicePrincipalType,passwordCredentials,keyCredentials,appRoles,accountEnabled&$top=999")
	if serr != nil {
		log.Printf("[argus/azure] identity service principals error: %v", serr)
	}
	for _, s := range sps {
		sp := models.ServicePrincipal{
			ID:                   jsonString(s, "id"),
			DisplayName:          jsonString(s, "displayName"),
			AppID:                jsonString(s, "appId"),
			ServicePrincipalType: jsonString(s, "servicePrincipalType"),
			PasswordCredentials:  parseCredentials(s["passwordCredentials"]),
			KeyCredentials:       parseCredentials(s["keyCredentials"]),
			AppRoles:             []string{},
		}
		if v, ok := s["accountEnabled"].(bool); ok {
			sp.AccountEnabled = v
		}
		if roles, ok := s["appRoles"].([]interface{}); ok {
			for _, r := range roles {
				if rm, ok := r.(map[string]interface{}); ok {
					if name := jsonString(rm, "value"); name != "" {
						sp.AppRoles = append(sp.AppRoles, name)
					}
				}
			}
		}
		snap.ServicePrincipals = append(snap.ServicePrincipals, sp)
	}

	// ---- App Registrations ----
	apps, aerr := gc.getPaged(ctx, "/applications?$select=id,displayName,appId,passwordCredentials,requiredResourceAccess&$top=999")
	if aerr != nil {
		log.Printf("[argus/azure] identity applications error: %v", aerr)
	}
	for _, a := range apps {
		app := models.AppRegistration{
			ID:                     jsonString(a, "id"),
			DisplayName:            jsonString(a, "displayName"),
			AppID:                  jsonString(a, "appId"),
			PasswordCredentials:    parseCredentials(a["passwordCredentials"]),
			RequiredResourceAccess: []models.ResourceAccess{},
		}
		if rra, ok := a["requiredResourceAccess"].([]interface{}); ok {
			for _, r := range rra {
				rm, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				access := models.ResourceAccess{
					ResourceAppID: jsonString(rm, "resourceAppId"),
					Permissions:   []models.Permission{},
				}
				if perms, ok := rm["resourceAccess"].([]interface{}); ok {
					for _, p := range perms {
						if pm, ok := p.(map[string]interface{}); ok {
							access.Permissions = append(access.Permissions, models.Permission{
								ID:   jsonString(pm, "id"),
								Type: jsonString(pm, "type"),
							})
						}
					}
				}
				app.RequiredResourceAccess = append(app.RequiredResourceAccess, access)
			}
		}
		snap.AppRegistrations = append(snap.AppRegistrations, app)
	}

	// ---- Conditional Access Policies ----
	caps, cerr := gc.getPaged(ctx, "/identity/conditionalAccess/policies")
	if cerr != nil {
		log.Printf("[argus/azure] identity CAP error: %v", cerr)
	}
	for _, c := range caps {
		capPol := models.ConditionalAccessPolicy{
			ID:            jsonString(c, "id"),
			DisplayName:   jsonString(c, "displayName"),
			State:         jsonString(c, "state"),
			Conditions:    map[string]interface{}{},
			GrantControls: map[string]interface{}{},
		}
		if v, ok := c["conditions"].(map[string]interface{}); ok {
			capPol.Conditions = v
		}
		if v, ok := c["grantControls"].(map[string]interface{}); ok {
			capPol.GrantControls = v
		}
		snap.ConditionalAccess = append(snap.ConditionalAccess, capPol)
	}

	// ---- RBAC role assignments (directory-scoped) ----
	ras, raerr := gc.getPaged(ctx, "/roleManagement/directory/roleAssignments")
	if raerr != nil {
		log.Printf("[argus/azure] identity role assignments error: %v", raerr)
	}
	// Load role definitions so we can decorate assignment with the role name.
	roleDefs := map[string]string{}
	rdefs, _ := gc.getPaged(ctx, "/roleManagement/directory/roleDefinitions?$select=id,displayName")
	for _, rd := range rdefs {
		if id := jsonString(rd, "id"); id != "" {
			roleDefs[id] = jsonString(rd, "displayName")
		}
	}
	for _, raw := range ras {
		ra := models.RoleAssignment{
			ID:               jsonString(raw, "id"),
			RoleDefinitionID: jsonString(raw, "roleDefinitionId"),
			PrincipalID:      jsonString(raw, "principalId"),
			PrincipalType:    jsonString(raw, "principalType"),
			Scope:            jsonString(raw, "directoryScopeId"),
		}
		if n, ok := roleDefs[ra.RoleDefinitionID]; ok {
			ra.RoleName = n
		}
		snap.RoleAssignments = append(snap.RoleAssignments, ra)
	}

	// ---- PIM: eligible + active ----
	eligible, _ := gc.getPaged(ctx, "/roleManagement/directory/roleEligibilityScheduleInstances")
	for _, e := range eligible {
		snap.PIMAssignments = append(snap.PIMAssignments, parsePIM(e, "Eligible", roleDefs))
	}
	active, _ := gc.getPaged(ctx, "/roleManagement/directory/roleAssignmentScheduleInstances")
	for _, e := range active {
		snap.PIMAssignments = append(snap.PIMAssignments, parsePIM(e, "Active", roleDefs))
	}

	// ---- Access reviews ----
	revs, rerr := gc.getPaged(ctx, "/identityGovernance/accessReviews/definitions")
	if rerr != nil {
		log.Printf("[argus/azure] identity access reviews error: %v", rerr)
	}
	for _, r := range revs {
		rv := models.AccessReview{
			ID:          jsonString(r, "id"),
			DisplayName: jsonString(r, "displayName"),
			Status:      jsonString(r, "status"),
			Reviewers:   []string{},
		}
		if scope, ok := r["scope"].(map[string]interface{}); ok {
			rv.Scope = jsonString(scope, "query")
		}
		if rvws, ok := r["reviewers"].([]interface{}); ok {
			for _, rr := range rvws {
				if rm, ok := rr.(map[string]interface{}); ok {
					rv.Reviewers = append(rv.Reviewers, jsonString(rm, "query"))
				}
			}
		}
		snap.AccessReviews = append(snap.AccessReviews, rv)
	}

	// ---- Tenant settings ----
	snap.TenantSettings = fetchTenantSettings(ctx, gc)

	// Managed identities are discovered from the Resource Graph side (they
	// live on resources) — identity.go doesn't populate them. Leave the
	// slice empty and let resources.go fill it via a later pass if needed.

	_ = tenantID // kept for future use (e.g. targeted graph scope headers)
	return snap, gc.MissingScopes(), nil
}

// parsePIM converts a PIM schedule instance into a PIMAssignment. The
// directoryScopeId field is populated for tenant-wide roles (value "/")
// and for AU-scoped assignments ("/administrativeUnits/<id>"); we carry
// it through so the pathfinder can place the has_role edge on the right
// node (tenant root vs. a specific AU).
func parsePIM(raw map[string]interface{}, kind string, roleDefs map[string]string) models.PIMAssignment {
	p := models.PIMAssignment{
		ID:               jsonString(raw, "id"),
		RoleDefinitionID: jsonString(raw, "roleDefinitionId"),
		PrincipalID:      jsonString(raw, "principalId"),
		AssignmentType:   kind,
		Scope:            jsonString(raw, "directoryScopeId"),
		StartDateTime:    jsonString(raw, "startDateTime"),
		EndDateTime:      jsonString(raw, "endDateTime"),
	}
	// Microsoft Graph exposes principalType on schedule instances as of
	// the beta surface and the v1.0 response includes it for GA roles;
	// fall back to "User" when absent since Entra PIM overwhelmingly
	// targets users and directly-enabled groups.
	p.PrincipalType = jsonString(raw, "principalType")
	if p.PrincipalType == "" {
		p.PrincipalType = "User"
	}
	if p.Scope == "" {
		p.Scope = "/"
	}
	if n, ok := roleDefs[p.RoleDefinitionID]; ok {
		p.RoleName = n
	}
	return p
}

// parseCredentials turns a Graph credential list (passwordCredentials or
// keyCredentials) into the model shape.
func parseCredentials(raw interface{}) []models.Credential {
	out := []models.Credential{}
	arr, ok := raw.([]interface{})
	if !ok {
		return out
	}
	for _, a := range arr {
		m, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, models.Credential{
			KeyID:         jsonString(m, "keyId"),
			StartDateTime: jsonString(m, "startDateTime"),
			EndDateTime:   jsonString(m, "endDateTime"),
			DisplayName:   jsonString(m, "displayName"),
		})
	}
	return out
}

// fetchTenantSettings queries the authentication methods policy and the
// cross-tenant access policy and reshapes them into TenantSettings.
func fetchTenantSettings(ctx context.Context, gc *graphClient) models.TenantSettings {
	ts := models.TenantSettings{
		GuestUserPermissions:          "Unknown",
		GuestInviteRestrictions:       "Unknown",
		CrossTenantAccessUnrestricted: false,
		PasswordResetNotification:     false,
		LegacyAuthEnabled:             false,
	}

	// Authentication methods policy — surfaces legacy auth state. The
	// payload is a deeply nested object; we only extract the top-level
	// signals we care about.
	var authPolicy map[string]interface{}
	if status, err := gc.get(ctx, "/policies/authenticationMethodsPolicy", &authPolicy); err == nil {
		// If the "authenticationMethodConfigurations" array contains any
		// entry with "state": "enabled" for legacy methods, flag it.
		if cfgs, ok := authPolicy["authenticationMethodConfigurations"].([]interface{}); ok {
			for _, c := range cfgs {
				cm, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				name := strings.ToLower(jsonString(cm, "id"))
				state := strings.ToLower(jsonString(cm, "state"))
				if state == "enabled" && (name == "email" || name == "sms" || name == "voice") {
					ts.LegacyAuthEnabled = true
					break
				}
			}
		}
	} else {
		log.Printf("[argus/azure] tenant auth policy soft-failed: %v", err)
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			gc.recordMissingScope("/policies/authenticationMethodsPolicy")
		}
	}

	// Cross-tenant access policy.
	var ctap map[string]interface{}
	if status, err := gc.get(ctx, "/policies/crossTenantAccessPolicy/default", &ctap); err == nil {
		if inbound, ok := ctap["inboundTrust"].(map[string]interface{}); ok {
			if v, ok := inbound["isMfaAccepted"].(bool); ok && !v {
				ts.CrossTenantAccessUnrestricted = true
			}
		}
	} else {
		log.Printf("[argus/azure] cross-tenant policy soft-failed: %v", err)
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			gc.recordMissingScope("/policies/crossTenantAccessPolicy")
		}
	}

	// Authorization policy — guest user permission level and invite restrictions.
	var authz map[string]interface{}
	if status, err := gc.get(ctx, "/policies/authorizationPolicy", &authz); err == nil {
		if v := jsonString(authz, "guestUserRoleId"); v != "" {
			// Known guest role GUIDs.
			switch v {
			case "10dae51f-b6af-4016-8d66-8c2a99b929b3":
				ts.GuestUserPermissions = "None"
			case "2af84b1e-32c8-42b7-82bc-daa82404023b":
				ts.GuestUserPermissions = "LimitedAccess"
			case "a0b1b346-4d3e-4e8b-98f8-753987be4970":
				ts.GuestUserPermissions = "FullAccess"
			default:
				ts.GuestUserPermissions = "Custom"
			}
		}
		if v := jsonString(authz, "allowInvitesFrom"); v != "" {
			ts.GuestInviteRestrictions = v
		}
	} else {
		log.Printf("[argus/azure] authorization policy soft-failed: %v", err)
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			gc.recordMissingScope("/policies/authorizationPolicy")
		}
	}

	return ts
}

// jsonString is a tiny helper for reading string fields out of a
// map[string]interface{} produced by json.Unmarshal.
func jsonString(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}
