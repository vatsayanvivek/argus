// Package monitor implements a continuous polling loop that periodically
// scans Azure subscriptions via the OPA pipeline, computes deltas against
// previous results, and optionally fires webhook notifications when the
// security score drifts beyond a configurable threshold.
package monitor

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/collector/azure"
	"github.com/vatsayanvivek/argus/internal/config"
	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/models"
	"github.com/vatsayanvivek/argus/internal/scorer"
	"github.com/vatsayanvivek/argus/internal/webhooks"
)

// maxHistory is the number of past scan snapshots retained per subscription.
const maxHistory = 10

// Monitor continuously scans one or more Azure subscriptions on a fixed
// interval, comparing each result with the previous scan and optionally
// sending webhook notifications when the security score drifts.
type Monitor struct {
	TenantID       string
	SubscriptionID string // empty = discover all subscriptions
	Interval       time.Duration
	WebhookOnDrift bool
	Config         *config.Config

	// ScanFunc can be replaced in tests to avoid real Azure calls.
	// When nil, the default OPA pipeline (collect -> evaluate -> correlate -> score) is used.
	ScanFunc func(ctx context.Context, subscriptionID, tenantID string) (*ScanResult, error)

	mu      sync.Mutex
	history map[string][]*ScanResult // subscriptionID -> recent results (newest last)
}

// ScanResult captures the output of a single scan cycle for one subscription.
type ScanResult struct {
	SubscriptionID string
	Score          float64
	TotalFindings  int
	TotalChains    int
	Timestamp      time.Time
}

// ScanDelta describes the difference between two consecutive scans for
// a single subscription.
type ScanDelta struct {
	SubscriptionID   string
	PreviousScore    float64
	CurrentScore     float64
	ScoreDelta       float64
	NewFindings      int
	ResolvedFindings int
	NewChains        int
	ResolvedChains   int
	Timestamp        time.Time
}

// Run starts the continuous monitoring loop. It blocks until ctx is
// cancelled, returning nil on clean shutdown and ctx.Err() otherwise.
func (m *Monitor) Run(ctx context.Context) error {
	m.mu.Lock()
	if m.history == nil {
		m.history = make(map[string][]*ScanResult)
	}
	m.mu.Unlock()

	for {
		cycleStart := time.Now().UTC()

		subs := []string{m.SubscriptionID}
		if m.SubscriptionID == "" {
			discovered, err := m.discoverSubscriptions(ctx)
			if err != nil {
				fmt.Printf("[%s] ERROR discovering subscriptions: %v\n",
					cycleStart.Format(time.RFC3339), err)
			} else {
				subs = discovered
			}
		}

		for _, sub := range subs {
			if err := ctx.Err(); err != nil {
				return nil
			}
			m.scanAndReport(ctx, sub)
		}

		// Sleep until the next cycle, respecting context cancellation.
		fmt.Printf("[%s] Sleeping for %s until next scan cycle\n",
			time.Now().UTC().Format(time.RFC3339), m.Interval)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(m.Interval):
			// continue to next cycle
		}
	}
}

// scanAndReport runs a single scan for the given subscription, computes
// the delta against the most recent previous scan, logs a status line,
// and fires webhooks if drift exceeds the threshold.
func (m *Monitor) scanAndReport(ctx context.Context, subscriptionID string) {
	ts := time.Now().UTC()

	result, err := m.runScan(ctx, subscriptionID)
	if err != nil {
		fmt.Printf("[%s] %s: ERROR: %v\n", ts.Format(time.RFC3339), subscriptionID, err)
		return
	}

	delta := m.computeDelta(subscriptionID, result)
	m.recordResult(subscriptionID, result)
	m.printStatus(delta, m.Interval)

	if m.WebhookOnDrift && math.Abs(delta.ScoreDelta) > 5.0 {
		m.fireWebhooks(delta)
	}
}

// runScan executes the scan pipeline for a single subscription. If
// ScanFunc is set (e.g. in tests), it delegates to that instead.
func (m *Monitor) runScan(ctx context.Context, subscriptionID string) (*ScanResult, error) {
	if m.ScanFunc != nil {
		return m.ScanFunc(ctx, subscriptionID, m.TenantID)
	}
	return defaultScan(ctx, subscriptionID, m.TenantID)
}

// defaultScan runs the full OPA pipeline: collect resources, evaluate
// policies, correlate attack chains, and score.
func defaultScan(ctx context.Context, subscriptionID, tenantID string) (*ScanResult, error) {
	collector, err := azure.NewCollector(subscriptionID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("collector init: %w", err)
	}

	snapshot, err := collector.CollectAll(ctx)
	if err != nil {
		// Partial results are OK — keep going.
		fmt.Printf("[monitor] collection warning for %s: %v\n", subscriptionID, err)
	}
	if snapshot == nil {
		snapshot = &models.AzureSnapshot{
			SubscriptionID: subscriptionID,
			TenantID:       tenantID,
			ScanTime:       time.Now().UTC(),
			CollectionMode: "minimal",
		}
	}

	loader, err := benchmark.NewBenchmarkLoader()
	if err != nil {
		return nil, fmt.Errorf("benchmark loader: %w", err)
	}

	opaEngine, err := engine.NewOPAEngine()
	if err != nil {
		return nil, fmt.Errorf("OPA engine init: %w", err)
	}

	findings, err := opaEngine.Evaluate(snapshot, "all")
	if err != nil {
		return nil, fmt.Errorf("policy evaluation: %w", err)
	}
	for i := range findings {
		benchmark.EnrichFinding(&findings[i], loader)
	}

	correlator := engine.NewCorrelator()
	chains := correlator.Correlate(findings, snapshot)

	scoringEngine := scorer.NewScorer()
	scoreReport := scoringEngine.Score(findings, chains, snapshot)

	return &ScanResult{
		SubscriptionID: subscriptionID,
		Score:          scoreReport.OverallScore,
		TotalFindings:  len(findings),
		TotalChains:    len(chains),
		Timestamp:      time.Now().UTC(),
	}, nil
}

// discoverSubscriptions uses the Azure collector to list all enabled
// subscriptions in the tenant. This is a best-effort helper; callers
// should fall back gracefully on error.
func (m *Monitor) discoverSubscriptions(ctx context.Context) ([]string, error) {
	// We need a credential to list subscriptions. Create a temporary
	// collector to obtain one, then call the package-level list function.
	collector, err := azure.NewCollector("", m.TenantID)
	if err != nil {
		return nil, err
	}
	subs, err := azure.ListSubscriptions(ctx, collector.Credential())
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(subs))
	for i, s := range subs {
		ids[i] = s.ID
	}
	return ids, nil
}

// computeDelta computes the difference between the latest stored scan
// and the new result. If there is no previous scan, the delta shows
// zero change.
func (m *Monitor) computeDelta(subscriptionID string, current *ScanResult) ScanDelta {
	m.mu.Lock()
	defer m.mu.Unlock()

	history := m.history[subscriptionID]
	delta := ScanDelta{
		SubscriptionID: subscriptionID,
		CurrentScore:   current.Score,
		Timestamp:      current.Timestamp,
	}

	if len(history) == 0 {
		// First scan — no previous data.
		delta.PreviousScore = current.Score
		delta.ScoreDelta = 0
		delta.NewFindings = current.TotalFindings
		delta.NewChains = current.TotalChains
		return delta
	}

	prev := history[len(history)-1]
	delta.PreviousScore = prev.Score
	delta.ScoreDelta = current.Score - prev.Score

	if current.TotalFindings > prev.TotalFindings {
		delta.NewFindings = current.TotalFindings - prev.TotalFindings
	} else {
		delta.ResolvedFindings = prev.TotalFindings - current.TotalFindings
	}

	if current.TotalChains > prev.TotalChains {
		delta.NewChains = current.TotalChains - prev.TotalChains
	} else {
		delta.ResolvedChains = prev.TotalChains - current.TotalChains
	}

	return delta
}

// recordResult appends a scan result to the per-subscription history,
// evicting the oldest entry if the history exceeds maxHistory.
func (m *Monitor) recordResult(subscriptionID string, result *ScanResult) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.history[subscriptionID] = append(m.history[subscriptionID], result)
	if len(m.history[subscriptionID]) > maxHistory {
		m.history[subscriptionID] = m.history[subscriptionID][1:]
	}
}

// printStatus writes a single-line summary for the scan cycle.
func (m *Monitor) printStatus(delta ScanDelta, interval time.Duration) {
	sign := "+"
	if delta.ScoreDelta < 0 {
		sign = ""
	}

	findingsStr := ""
	if delta.NewFindings > 0 {
		findingsStr += fmt.Sprintf("+%d findings", delta.NewFindings)
	}
	if delta.ResolvedFindings > 0 {
		if findingsStr != "" {
			findingsStr += ", "
		}
		findingsStr += fmt.Sprintf("-%d findings", delta.ResolvedFindings)
	}

	chainsStr := ""
	if delta.NewChains > 0 {
		chainsStr += fmt.Sprintf("+%d chains", delta.NewChains)
	}
	if delta.ResolvedChains > 0 {
		if chainsStr != "" {
			chainsStr += ", "
		}
		chainsStr += fmt.Sprintf("-%d chains", delta.ResolvedChains)
	}

	detail := ""
	if findingsStr != "" || chainsStr != "" {
		parts := []string{}
		if findingsStr != "" {
			parts = append(parts, findingsStr)
		}
		if chainsStr != "" {
			parts = append(parts, chainsStr)
		}
		detail = " | "
		for i, p := range parts {
			if i > 0 {
				detail += ", "
			}
			detail += p
		}
	}

	fmt.Printf("[%s] %s: Score %.1f -> %.1f (D%s%.1f)%s | next scan in %s\n",
		delta.Timestamp.Format(time.RFC3339),
		delta.SubscriptionID,
		delta.PreviousScore,
		delta.CurrentScore,
		sign,
		delta.ScoreDelta,
		detail,
		interval,
	)
}

// fireWebhooks sends a drift notification to all configured webhooks.
func (m *Monitor) fireWebhooks(delta ScanDelta) {
	if m.Config == nil || len(m.Config.Webhooks) == 0 {
		fmt.Printf("[monitor] drift detected (D%.1f) but no webhooks configured\n", delta.ScoreDelta)
		return
	}

	notifier := webhooks.NewNotifier()
	summary := webhooks.ScanSummary{
		SubscriptionID: delta.SubscriptionID,
		TenantID:       m.TenantID,
		ScanTime:       delta.Timestamp.Format(time.RFC3339),
		OverallScore:   delta.CurrentScore,
		TotalFindings:  delta.NewFindings,
	}

	// Convert config webhooks to the webhooks package type.
	whConfigs := make([]webhooks.WebhookConfig, len(m.Config.Webhooks))
	for i, wh := range m.Config.Webhooks {
		whConfigs[i] = webhooks.WebhookConfig{
			Name:    wh.Name,
			URL:     wh.URL,
			Format:  wh.Format,
			Events:  wh.Events,
			Timeout: wh.Timeout,
			Headers: wh.Headers,
		}
	}

	if errs := notifier.Send(summary, whConfigs); len(errs) > 0 {
		for _, err := range errs {
			fmt.Printf("[monitor] webhook error: %v\n", err)
		}
	}
}

// ComputeDelta is an exported wrapper around the delta computation logic,
// useful for testing. It takes two scan results and returns the delta.
func ComputeDelta(prev, current *ScanResult) ScanDelta {
	delta := ScanDelta{
		SubscriptionID: current.SubscriptionID,
		CurrentScore:   current.Score,
		Timestamp:      current.Timestamp,
	}

	if prev == nil {
		delta.PreviousScore = current.Score
		delta.ScoreDelta = 0
		delta.NewFindings = current.TotalFindings
		delta.NewChains = current.TotalChains
		return delta
	}

	delta.PreviousScore = prev.Score
	delta.ScoreDelta = current.Score - prev.Score

	if current.TotalFindings > prev.TotalFindings {
		delta.NewFindings = current.TotalFindings - prev.TotalFindings
	} else {
		delta.ResolvedFindings = prev.TotalFindings - current.TotalFindings
	}

	if current.TotalChains > prev.TotalChains {
		delta.NewChains = current.TotalChains - prev.TotalChains
	} else {
		delta.ResolvedChains = prev.TotalChains - current.TotalChains
	}

	return delta
}
