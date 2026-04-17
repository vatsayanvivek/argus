package drift

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

//go:embed builtin_roles.json
var builtinRolesFS embed.FS

// RoleDefinition is a parsed Azure role definition (built-in or custom).
// The field set mirrors what the ARM roleDefinitions API returns so the
// same struct can be populated from the embedded catalogue or from a
// live API call.
type RoleDefinition struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	RoleType       string   `json:"roleType"`
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

// builtinRolesFile is the structure of the embedded JSON file.
type builtinRolesFile struct {
	Roles []RoleDefinition `json:"roles"`
}

// RoleResolver fetches role definitions, caches them, and falls back
// to a bundled list of common Azure built-in roles when the live API
// is unavailable. Safe for concurrent use.
type RoleResolver struct {
	mu       sync.RWMutex
	cache    map[string]*RoleDefinition // keyed by role definition ID (last UUID segment)
	builtins map[string]*RoleDefinition // keyed by both lowercase name and ID
	cred     azcore.TokenCredential
	sub      string
	http     *http.Client
}

// NewRoleResolver loads the built-in role catalogue from the embedded
// file. The credential and subscription are stored for later live API
// calls; pass nil credential to operate in offline-only mode.
func NewRoleResolver(cred azcore.TokenCredential, subscriptionID string) (*RoleResolver, error) {
	raw, err := builtinRolesFS.ReadFile("builtin_roles.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded builtin_roles.json: %w", err)
	}
	var file builtinRolesFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse embedded builtin_roles.json: %w", err)
	}

	builtins := make(map[string]*RoleDefinition, len(file.Roles)*2)
	for i := range file.Roles {
		rd := &file.Roles[i]
		if rd.ID != "" {
			builtins[strings.ToLower(rd.ID)] = rd
		}
		if rd.Name != "" {
			builtins[strings.ToLower(rd.Name)] = rd
		}
	}

	return &RoleResolver{
		cache:    make(map[string]*RoleDefinition),
		builtins: builtins,
		cred:     cred,
		sub:      subscriptionID,
		http:     &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// extractRoleID returns the trailing UUID of an Azure role definition
// resource ID. For inputs like
// "/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/8e3af657-..."
// it returns just "8e3af657-...". Inputs that are already bare UUIDs
// are returned unchanged.
func extractRoleID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.LastIndex(raw, "/"); idx >= 0 {
		return raw[idx+1:]
	}
	return raw
}

// Resolve looks up a role definition by ID. Tries live ARM API first
// if a credential was provided, falls back to the built-in catalogue,
// returns nil + error if neither has it.
func (r *RoleResolver) Resolve(ctx context.Context, roleDefinitionID string) (*RoleDefinition, error) {
	id := extractRoleID(roleDefinitionID)
	if id == "" {
		return nil, fmt.Errorf("empty role definition id")
	}
	key := strings.ToLower(id)

	// Cache hit?
	r.mu.RLock()
	if rd, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return rd, nil
	}
	r.mu.RUnlock()

	// Live API if we have credentials.
	if r.cred != nil && r.sub != "" {
		if rd, err := r.fetchLive(ctx, id); err == nil && rd != nil {
			r.mu.Lock()
			r.cache[key] = rd
			r.mu.Unlock()
			return rd, nil
		}
	}

	// Offline fallback.
	if rd, ok := r.builtins[key]; ok {
		r.mu.Lock()
		r.cache[key] = rd
		r.mu.Unlock()
		return rd, nil
	}

	return nil, fmt.Errorf("role definition %q not found in live ARM or built-in catalogue", id)
}

// ResolveByName matches case-insensitively against the role display
// name. Useful for the drift analyzer which sees role names from
// RoleAssignment.RoleName. Only consults the built-in catalogue.
func (r *RoleResolver) ResolveByName(name string) *RoleDefinition {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return nil
	}
	if rd, ok := r.builtins[key]; ok {
		return rd
	}
	return nil
}

// fetchLive calls the Azure ARM roleDefinitions endpoint using
// net/http directly to keep the dependency footprint small. Any
// failure returns an error so callers can fall back to the embedded
// catalogue. This is a best-effort, soft-failing call.
func (r *RoleResolver) fetchLive(ctx context.Context, roleDefID string) (*RoleDefinition, error) {
	if r.cred == nil || r.sub == "" {
		return nil, fmt.Errorf("no credential or subscription configured")
	}

	tok, err := r.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("acquire ARM token: %w", err)
	}

	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s?api-version=2022-04-01",
		r.sub, roleDefID,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ARM call: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ARM response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ARM returned %d: %s", resp.StatusCode, truncateStr(string(body), 256))
	}

	// The ARM response shape is:
	// { "id": "...", "name": "<guid>", "type": "...",
	//   "properties": { "roleName": "...", "description": "...",
	//                   "type": "BuiltInRole", "permissions": [
	//                     {"actions": [...], "notActions": [...],
	//                      "dataActions": [...], "notDataActions": [...]}
	//                   ]}}
	var envelope struct {
		Name       string `json:"name"`
		Properties struct {
			RoleName    string `json:"roleName"`
			Description string `json:"description"`
			RoleType    string `json:"type"`
			Permissions []struct {
				Actions        []string `json:"actions"`
				NotActions     []string `json:"notActions"`
				DataActions    []string `json:"dataActions"`
				NotDataActions []string `json:"notDataActions"`
			} `json:"permissions"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse ARM response: %w", err)
	}

	rd := &RoleDefinition{
		ID:          envelope.Name,
		Name:        envelope.Properties.RoleName,
		Description: envelope.Properties.Description,
		RoleType:    envelope.Properties.RoleType,
	}
	for _, p := range envelope.Properties.Permissions {
		rd.Actions = append(rd.Actions, p.Actions...)
		rd.NotActions = append(rd.NotActions, p.NotActions...)
		rd.DataActions = append(rd.DataActions, p.DataActions...)
		rd.NotDataActions = append(rd.NotDataActions, p.NotDataActions...)
	}
	return rd, nil
}

// ExpandActions takes a role's Actions list and expands wildcards
// like "Microsoft.Compute/*" into a representative list of operations
// using a bundled resource-provider operation catalogue. For a bare
// "*" the expansion is the entire catalogue (~500 ops). NotActions
// are removed from the expanded set before returning. Results are
// deduplicated and sorted alphabetically.
func (r *RoleResolver) ExpandActions(role *RoleDefinition) []string {
	if role == nil {
		return nil
	}

	expanded := map[string]struct{}{}
	addAll := func(list []string) {
		for _, a := range list {
			expanded[a] = struct{}{}
		}
	}

	for _, a := range role.Actions {
		if a == "*" {
			// Full wildcard — dump the whole catalogue.
			addAll(commonAzureOperations)
			continue
		}
		if strings.Contains(a, "*") {
			addAll(matchCatalogue(a))
			// Also retain the pattern itself so the analyzer can
			// display it verbatim when reporting unused patterns.
			expanded[a] = struct{}{}
			continue
		}
		expanded[a] = struct{}{}
	}

	// Fold in data actions alongside control-plane actions.
	for _, a := range role.DataActions {
		if a == "*" {
			addAll(commonAzureOperations)
			continue
		}
		if strings.Contains(a, "*") {
			addAll(matchCatalogue(a))
			expanded[a] = struct{}{}
			continue
		}
		expanded[a] = struct{}{}
	}

	// Subtract NotActions / NotDataActions (wildcard-aware).
	remove := func(patterns []string) {
		if len(patterns) == 0 {
			return
		}
		for k := range expanded {
			for _, p := range patterns {
				if wildcardMatch(p, k) {
					delete(expanded, k)
					break
				}
			}
		}
	}
	remove(role.NotActions)
	remove(role.NotDataActions)

	out := make([]string, 0, len(expanded))
	for k := range expanded {
		out = append(out, k)
	}
	// Deterministic order for testability and copy-paste reports.
	sort.Strings(out)
	return out
}

// matchCatalogue returns every entry in commonAzureOperations whose
// string matches the given wildcard pattern. It's the engine behind
// ExpandActions for non-"*" wildcards.
func matchCatalogue(pattern string) []string {
	out := make([]string, 0, 16)
	for _, op := range commonAzureOperations {
		if wildcardMatch(pattern, op) {
			out = append(out, op)
		}
	}
	return out
}

// truncateStr clips a string to n runes for log safety.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}


