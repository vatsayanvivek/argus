// Package azure implements the ARGUS Azure collector. It gathers a complete
// snapshot of an Azure subscription and tenant, including resources, identity,
// Defender for Cloud findings, activity log, and policy compliance. All errors
// from the upstream Azure SDK are handled locally; the collector never crashes
// on a partial failure. Failures are recorded on snapshot.CollectionErrors and
// the collection still completes so downstream analysis can proceed.
package azure

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/vatsayanvivek/argus/internal/models"
)

// Collector is the top-level Azure collector. It owns one azidentity credential
// and orchestrates the five sub-collectors (resources, identity, defender,
// activity log, policy) in parallel.
type Collector struct {
	subscriptionID string
	tenantID       string
	credential     *azidentity.DefaultAzureCredential
}

// NewCollector constructs a Collector bound to a subscription and tenant. It
// builds a DefaultAzureCredential, which walks Azure CLI, environment
// variables, managed identity, and the rest of the default chain. Failure to
// build the credential is the only fatal error this collector can return —
// everything else is soft-failed.
func NewCollector(subscriptionID, tenantID string) (*Collector, error) {
	if subscriptionID == "" {
		return nil, fmt.Errorf("azure: subscription ID is required")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("azure: tenant ID is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure: failed to build DefaultAzureCredential: %w", err)
	}
	return &Collector{
		subscriptionID: subscriptionID,
		tenantID:       tenantID,
		credential:     cred,
	}, nil
}

// Credential returns the underlying DefaultAzureCredential so that
// other parts of ARGUS (subscription discovery, role definition
// fetcher) can reuse the same authentication context without building
// a second credential chain.
func (c *Collector) Credential() *azidentity.DefaultAzureCredential {
	return c.credential
}

// ProgressEvent describes one step of a collection run. Emitted by
// CollectAllWithProgress as each parallel sub-collector starts and
// completes. The CLI uses this to show live activity during the long
// collection phase so the user never stares at a stalled progress
// bar.
//
// Name is the human-readable sub-collector name (resources, identity,
// rbac, defender, activitylog, policy). Phase is "started" |
// "completed" | "failed". Detail is a short free-text message the
// sub-collector may emit ("42 resources enumerated"). Elapsed is the
// duration since the sub-collector began (always zero on "started").
type ProgressEvent struct {
	Name    string
	Phase   string
	Detail  string
	Elapsed time.Duration
	Err     error
}

// ProgressCallback receives ProgressEvent values as they happen. A
// nil callback disables reporting. The callback must be safe to call
// from multiple goroutines — CollectAll invokes it from inside each
// sub-collector goroutine.
type ProgressCallback func(ProgressEvent)

// CollectAll runs every sub-collector in parallel and returns a
// snapshot. See CollectAllWithProgress for per-collector progress
// reporting. This no-progress variant is kept so callers that don't
// need live status (unit tests, org-wide fanout) stay simple.
func (c *Collector) CollectAll(ctx context.Context) (*models.AzureSnapshot, error) {
	return c.CollectAllWithProgress(ctx, nil)
}

// CollectAllWithProgress is CollectAll plus a callback that fires as
// each parallel sub-collector starts and completes. The callback is
// called from multiple goroutines — implementations must be safe to
// call concurrently. Pass nil to get the no-report behaviour of
// CollectAll.
func (c *Collector) CollectAllWithProgress(ctx context.Context, onProgress ProgressCallback) (*models.AzureSnapshot, error) {
	snapshot := &models.AzureSnapshot{
		SubscriptionID:     c.subscriptionID,
		TenantID:           c.tenantID,
		ScanTime:           time.Now().UTC(),
		CollectionMode:     "full",
		Resources:          []models.AzureResource{},
		DefenderFindings:   []models.DefenderFinding{},
		DefenderPlans:      map[string]string{},
		PolicyCompliance:   []models.PolicyResult{},
		ActivityLog:        []models.ActivityEvent{},
		DiagnosticSettings: map[string]bool{},
		CollectionErrors:   []string{},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Per-collector success flags. These drive CollectionMode at the end.
	var (
		resourcesOK bool
		identityOK  bool
		defenderOK  bool
		activityOK  bool
		policyOK    bool
	)

	appendErr := func(service string, err error) {
		if err == nil {
			return
		}
		mu.Lock()
		snapshot.CollectionErrors = append(
			snapshot.CollectionErrors,
			fmt.Sprintf("%s: %s", service, err.Error()),
		)
		mu.Unlock()
		log.Printf("[argus/azure] WARN %s collection error: %v", service, err)
	}

	// emit is a nil-safe progress reporter. Each sub-collector wraps
	// its start + end in emit() calls so the CLI can tick a live
	// activity view while parallel goroutines run. Concurrent-safe
	// because the callback is expected to serialise internally (the
	// CLI uses a single mutex-guarded renderer).
	emit := func(name, phase, detail string, started time.Time, err error) {
		if onProgress == nil {
			return
		}
		onProgress(ProgressEvent{
			Name:    name,
			Phase:   phase,
			Detail:  detail,
			Elapsed: time.Since(started),
			Err:     err,
		})
	}

	// Resource Graph + network topology.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recoverTo("resources", &mu, snapshot)
		started := time.Now()
		emit("resources", "started", "Enumerating subscription resources via Resource Graph", started, nil)
		resources, network, err := collectResources(ctx, c.credential, c.subscriptionID)
		if err != nil {
			appendErr("resources", err)
		}
		mu.Lock()
		if len(resources) > 0 {
			snapshot.Resources = resources
		}
		// Always set the network topology struct — it may be zero-valued.
		snapshot.NetworkTopology = network
		if err == nil {
			resourcesOK = true
		}
		mu.Unlock()
		phase := "completed"
		if err != nil {
			phase = "failed"
		}
		emit("resources", phase, fmt.Sprintf("%d resources enumerated", len(resources)), started, err)
	}()

	// Azure AD identity surface.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recoverTo("identity", &mu, snapshot)
		started := time.Now()
		emit("identity", "started", "Fetching Entra ID users / groups / service principals / CAPs", started, nil)
		identity, missingScopes, err := collectIdentity(ctx, c.credential, c.tenantID)
		if err != nil {
			appendErr("identity", err)
		}
		mu.Lock()
		snapshot.Identity = identity
		// Surface Graph permission gaps so the report can render the
		// "limited Graph access" warning. Any missing scope means
		// CHAIN-002 (App Registration takeover) and several identity
		// rules cannot be reliably evaluated.
		if len(missingScopes) > 0 {
			snapshot.GraphPermissionsLimited = true
			snapshot.GraphPermissionsMissing = missingScopes
		}
		if err == nil {
			identityOK = true
		}
		mu.Unlock()
		phase := "completed"
		if err != nil {
			phase = "failed"
		}
		emit("identity", phase, fmt.Sprintf("%d users, %d groups, %d SPs",
			len(identity.Users), len(identity.Groups), len(identity.ServicePrincipals)),
			started, err)
	}()

	// Azure RBAC (resource-scope role assignments). Runs against the ARM
	// Authorization API, independent of Microsoft Graph, so a tenant
	// without Graph.Read still gets the full subscription RBAC picture
	// the pathfinder needs to discover privilege paths. We stash the
	// slice in a local and merge into the snapshot after Wait() so the
	// identity goroutine's whole-struct assignment cannot clobber it.
	var azureRBAC []models.RoleAssignment
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recoverTo("rbac", &mu, snapshot)
		started := time.Now()
		emit("rbac", "started", "Collecting Azure RBAC assignments from ARM", started, nil)
		rbac := collectAzureRBAC(ctx, c.credential, c.subscriptionID)
		mu.Lock()
		azureRBAC = rbac
		mu.Unlock()
		emit("rbac", "completed", fmt.Sprintf("%d role assignments", len(rbac)), started, nil)
	}()

	// Defender for Cloud (findings, plans, secure score).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recoverTo("defender", &mu, snapshot)
		started := time.Now()
		emit("defender", "started", "Querying Microsoft Defender for Cloud recommendations + secure score", started, nil)
		findings, plans, secureScore, err := collectDefender(ctx, c.credential, c.subscriptionID)
		if err != nil {
			appendErr("defender", err)
		}
		mu.Lock()
		if len(findings) > 0 {
			snapshot.DefenderFindings = findings
		}
		if len(plans) > 0 {
			snapshot.DefenderPlans = plans
		}
		snapshot.SecureScore = secureScore
		if err == nil {
			defenderOK = true
		}
		mu.Unlock()
		phase := "completed"
		if err != nil {
			phase = "failed"
		}
		emit("defender", phase, fmt.Sprintf("%d findings, score %.0f/100", len(findings), secureScore),
			started, err)
	}()

	// Activity Log (last 30 days, security-relevant operations).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recoverTo("activitylog", &mu, snapshot)
		started := time.Now()
		emit("activitylog", "started", "Pulling Activity Log events (30-day window)", started, nil)
		events, err := collectActivityLog(ctx, c.credential, c.subscriptionID)
		if err != nil {
			appendErr("activitylog", err)
		}
		mu.Lock()
		if len(events) > 0 {
			snapshot.ActivityLog = events
		}
		if err == nil {
			activityOK = true
		}
		mu.Unlock()
		phase := "completed"
		if err != nil {
			phase = "failed"
		}
		emit("activitylog", phase, fmt.Sprintf("%d events", len(events)), started, err)
	}()

	// Azure Policy compliance.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recoverTo("policy", &mu, snapshot)
		started := time.Now()
		emit("policy", "started", "Evaluating Azure Policy compliance assignments", started, nil)
		results, err := collectPolicy(ctx, c.credential, c.subscriptionID)
		if err != nil {
			appendErr("policy", err)
		}
		mu.Lock()
		if len(results) > 0 {
			snapshot.PolicyCompliance = results
		}
		if err == nil {
			policyOK = true
		}
		mu.Unlock()
		phase := "completed"
		if err != nil {
			phase = "failed"
		}
		emit("policy", phase, fmt.Sprintf("%d policies evaluated", len(results)), started, err)
	}()

	wg.Wait()

	// Merge Azure RBAC assignments into the identity snapshot now that
	// the identity goroutine can no longer overwrite them.
	snapshot.Identity.AzureRBACAssignments = azureRBAC

	// Derive CollectionMode from success flags.
	successCount := 0
	for _, ok := range []bool{resourcesOK, identityOK, defenderOK, activityOK, policyOK} {
		if ok {
			successCount++
		}
	}
	switch {
	case successCount == 5:
		snapshot.CollectionMode = "full"
	case successCount == 0:
		snapshot.CollectionMode = "minimal"
	default:
		snapshot.CollectionMode = "partial"
	}

	// CollectAll never returns an error — the CollectionErrors slice is the
	// source of truth for partial failures. Callers always get a non-nil
	// snapshot so the rest of the pipeline can continue.
	return snapshot, nil
}

// recoverTo is deferred inside each sub-collector goroutine. A panic here —
// extremely unlikely but still possible on a nil map deref in an SDK response
// type — is converted into a CollectionError so the parent goroutine never
// crashes the process.
func recoverTo(service string, mu *sync.Mutex, snapshot *models.AzureSnapshot) {
	if r := recover(); r != nil {
		mu.Lock()
		snapshot.CollectionErrors = append(
			snapshot.CollectionErrors,
			fmt.Sprintf("%s: panic recovered: %v", service, r),
		)
		mu.Unlock()
		log.Printf("[argus/azure] PANIC in %s collector: %v", service, r)
	}
}

// classifyAzureError inspects an error returned by any azure-sdk-for-go call
// and decides whether it is a soft failure (403/404/NotFound) we should log
// and swallow, or a hard failure we should surface. Every call site in this
// package uses it so the "never crash on 403" rule is enforced in one place.
func classifyAzureError(err error) (soft bool, statusCode int) {
	if err == nil {
		return true, 0
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case 401, 403, 404, 501:
			return true, respErr.StatusCode
		case 500, 502, 503, 504:
			// Treat server errors as soft so transient backend outages don't
			// fail the whole scan — we still log them, but they don't abort.
			return true, respErr.StatusCode
		default:
			return false, respErr.StatusCode
		}
	}
	return false, 0
}
