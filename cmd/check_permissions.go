package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// checkPermissionsCmd probes every Microsoft Graph scope and ARM
// authorization scope ARGUS relies on, and reports which are available
// to the scanning identity. The primary use case is preflight before
// an enterprise rollout: operators run this against their target
// tenant and see, at a glance, which features will be evaluated (full
// scan) versus soft-failed (partial coverage).
//
// The check never modifies state. Every probe is a GET; a 200 means
// "have access"; 401/403 means "missing scope"; anything else is
// reported verbatim so the user can investigate.
var checkPermissionsCmd = &cobra.Command{
	Use:   "check-permissions",
	Short: "Preflight: report which Graph + ARM scopes the current identity has",
	Long: `Probe every Microsoft Graph API and Azure ARM authorization scope
ARGUS uses for a scan, and report which are granted vs missing.

Useful before running a full scan so you know up front whether PIM,
Conditional Access, Access Reviews, or Azure RBAC collection will be
available — or whether you need to grant additional scopes first.

Exit codes:
  0  - all required scopes granted
  1  - preflight could not run (no credential chain)
  2  - one or more scopes missing (scan will partial-fail on those)

Required flag:
  --tenant   Azure tenant ID (same value you'd pass to 'argus scan')`,
	RunE: runCheckPermissions,
}

var (
	checkPermissionsTenant string
	checkPermissionsJSON   bool
)

func init() {
	checkPermissionsCmd.Flags().StringVar(&checkPermissionsTenant, "tenant", "", "Azure tenant ID (required)")
	checkPermissionsCmd.Flags().BoolVar(&checkPermissionsJSON, "json", false, "Emit machine-readable JSON instead of the text table")
	_ = checkPermissionsCmd.MarkFlagRequired("tenant")
	rootCmd.AddCommand(checkPermissionsCmd)
}

// scopeProbe describes one API endpoint we'll GET to test for access.
// The Graph probe list mirrors the endpoints identity.go calls at
// scan time; any mismatch means the scan will hit the same 403 at
// real-scan time.
type scopeProbe struct {
	name        string // human-readable name
	url         string // absolute URL we'll GET
	tokenScope  string // OAuth audience
	requires    string // Graph/ARM scope the operator needs to grant
	featureImpact string // what breaks if this scope is missing
}

// graphProbes covers the Microsoft Graph endpoints ARGUS calls in
// collectIdentity. If any of these 403, the corresponding rule family
// will silently skip. This check surfaces the problem at preflight
// instead of mid-scan.
var graphProbes = []scopeProbe{
	{"Users", "https://graph.microsoft.com/v1.0/users?$top=1", "https://graph.microsoft.com/.default",
		"Directory.Read.All or User.Read.All", "Every identity rule (MFA, guest users, stale accounts)"},
	{"Groups", "https://graph.microsoft.com/v1.0/groups?$top=1", "https://graph.microsoft.com/.default",
		"Directory.Read.All or Group.Read.All", "Nested group pathfinder walks"},
	{"Group members", "https://graph.microsoft.com/v1.0/groups?$top=1&$select=id", "https://graph.microsoft.com/.default",
		"GroupMember.Read.All", "Transitive group membership"},
	{"Service Principals", "https://graph.microsoft.com/v1.0/servicePrincipals?$top=1", "https://graph.microsoft.com/.default",
		"Directory.Read.All or Application.Read.All", "Service principal posture rules"},
	{"Applications", "https://graph.microsoft.com/v1.0/applications?$top=1", "https://graph.microsoft.com/.default",
		"Application.Read.All", "App registration takeover detection (CHAIN-002)"},
	{"Conditional Access Policies", "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", "https://graph.microsoft.com/.default",
		"Policy.Read.All", "Conditional Access rules (zt_id_004, zt_id_006)"},
	{"Authentication Methods Policy", "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy", "https://graph.microsoft.com/.default",
		"Policy.Read.All", "Legacy auth detection"},
	{"Cross-Tenant Access Policy", "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default", "https://graph.microsoft.com/.default",
		"Policy.Read.All", "Cross-tenant trust rules (zt_id_017)"},
	{"Authorization Policy", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy", "https://graph.microsoft.com/.default",
		"Policy.Read.All", "Guest user permission rules"},
	{"Directory Role Assignments", "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$top=1", "https://graph.microsoft.com/.default",
		"RoleManagement.Read.Directory", "Entra directory role edges in pathfinder"},
	{"PIM Eligible Schedules", "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$top=1", "https://graph.microsoft.com/.default",
		"RoleManagement.Read.Directory", "PIM eligible assignments (zt_id_003, zt_id_007)"},
	{"PIM Active Schedules", "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$top=1", "https://graph.microsoft.com/.default",
		"RoleManagement.Read.Directory", "PIM active assignments"},
	{"Access Reviews", "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=1", "https://graph.microsoft.com/.default",
		"AccessReview.Read.All", "Access review existence rules (zt_id_010)"},
}

// armProbes covers the ARM endpoints ARGUS uses (Resource Graph, Authorization).
var armProbes = []scopeProbe{
	{"ARM Authorization (role assignments)", "https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$top=1", "https://management.azure.com/.default",
		"Reader on subscription", "Azure RBAC collection — blank pathfinder without it"},
	{"Resource Graph (resources)", "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", "https://management.azure.com/.default",
		"Reader on subscription", "Every resource-level rule"},
}

type probeResult struct {
	Probe       scopeProbe
	Status      int
	Err         string
	Granted     bool
}

func runCheckPermissions(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		TenantID: checkPermissionsTenant,
	})
	if err != nil {
		return fmt.Errorf("build credential: %w", err)
	}

	probes := append([]scopeProbe{}, graphProbes...)
	probes = append(probes, armProbes...)

	results := make([]probeResult, 0, len(probes))
	for _, p := range probes {
		results = append(results, probeOne(ctx, cred, p))
	}

	if checkPermissionsJSON {
		return emitJSON(results)
	}
	emitText(results)

	missing := 0
	for _, r := range results {
		if !r.Granted {
			missing++
		}
	}
	if missing > 0 {
		return &CIGateError{
			Message:  fmt.Sprintf("%d scope(s) missing — partial scan coverage", missing),
			ExitCode: 2,
		}
	}
	return nil
}

// probeOne fires a single GET and classifies the response.
func probeOne(ctx context.Context, cred *azidentity.DefaultAzureCredential, p scopeProbe) probeResult {
	res := probeResult{Probe: p}
	tk, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{p.tokenScope}})
	if err != nil {
		res.Err = "token acquisition failed: " + err.Error()
		return res
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("Authorization", "Bearer "+tk.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	// 200–399 means the call succeeded in some form. 404 on a Graph
	// endpoint with the right scope still counts as "granted" because
	// it merely says "no entity found", which is fine for preflight.
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 400, resp.StatusCode == 404:
		res.Granted = true
	case resp.StatusCode == 401, resp.StatusCode == 403:
		res.Err = fmt.Sprintf("HTTP %d — scope %q not granted", resp.StatusCode, p.requires)
	default:
		res.Err = fmt.Sprintf("HTTP %d (unexpected)", resp.StatusCode)
	}
	return res
}

// emitText renders the table for humans.
func emitText(results []probeResult) {
	bold := color.New(color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	fmt.Println(bold("\nARGUS scope preflight"))
	fmt.Println(dim("Probing Microsoft Graph + ARM endpoints used by the scanner."))
	fmt.Println()
	fmt.Printf("%-38s %-8s %-40s %s\n",
		bold("Endpoint"), bold("Status"), bold("Requires"), bold("If missing"))
	fmt.Println(strings.Repeat("─", 140))
	granted := 0
	for _, r := range results {
		mark := red("✗ missing")
		if r.Granted {
			mark = green("✓ granted")
			granted++
		}
		fmt.Printf("%-38s %-8s %-40s %s\n",
			r.Probe.name, mark, r.Probe.requires, dim(r.Probe.featureImpact))
		if !r.Granted && r.Err != "" {
			fmt.Printf("    %s %s\n", dim("↳"), dim(r.Err))
		}
	}
	fmt.Println(strings.Repeat("─", 140))
	fmt.Printf("%d / %d scopes granted\n", granted, len(results))

	missing := []string{}
	seen := map[string]bool{}
	for _, r := range results {
		if !r.Granted {
			for _, s := range strings.Split(r.Probe.requires, " or ") {
				s = strings.TrimSpace(s)
				if s != "" && !seen[s] {
					seen[s] = true
					missing = append(missing, s)
				}
			}
		}
	}
	if len(missing) == 0 {
		fmt.Println(green("\nAll required scopes granted — full-coverage scan available."))
		return
	}
	sort.Strings(missing)
	fmt.Println(red("\nMissing scopes:"))
	for _, m := range missing {
		fmt.Println("  • " + m)
	}
	fmt.Println(dim("\nGrant these to the scanning identity (Service Principal or user)."))
	fmt.Println(dim("See scripts/setup-graph-permissions.sh for an automated grant."))
}

// emitJSON emits the probe results as machine-readable JSON for CI.
func emitJSON(results []probeResult) error {
	out := map[string]interface{}{
		"tenant":      checkPermissionsTenant,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"total":       len(results),
		"probes":      results,
	}
	granted := 0
	for _, r := range results {
		if r.Granted {
			granted++
		}
	}
	out["granted"] = granted
	out["missing"] = len(results) - granted

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
