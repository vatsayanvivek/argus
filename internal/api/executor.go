// Package api provides the ARGUS HTTP API server and scan executor.
package api

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/collector/azure"
	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/models"
	"github.com/vatsayanvivek/argus/internal/scorer"
)

// ScanStatus represents the lifecycle state of a scan.
type ScanStatus string

const (
	StatusQueued    ScanStatus = "queued"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
)

// ScanRequest is the input for a new scan submission.
type ScanRequest struct {
	SubscriptionID string `json:"subscription_id"`
	TenantID       string `json:"tenant_id"`
	Compliance     string `json:"compliance"`
	Drift          bool   `json:"drift"`
}

// ScanResult stores the outcome of a completed scan.
type ScanResult struct {
	Score         float64 `json:"score"`
	Grade         string  `json:"grade"`
	FindingsCount int     `json:"findings_count"`
	ChainsCount   int     `json:"chains_count"`
	FullReport    any     `json:"full_report,omitempty"`
}

// ScanRecord tracks a single scan's state and result.
type ScanRecord struct {
	ScanID      string      `json:"scan_id"`
	Status      ScanStatus  `json:"status"`
	Request     ScanRequest `json:"request"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
	Result      *ScanResult `json:"result,omitempty"`
	Error       string      `json:"error,omitempty"`
}

// Executor manages concurrent scan execution with a bounded worker pool.
type Executor interface {
	Submit(req ScanRequest) *ScanRecord
	Get(scanID string) (*ScanRecord, bool)
	List() []*ScanRecord
}

// executor is the production implementation backed by the real ARGUS pipeline.
type executor struct {
	mu      sync.RWMutex
	scans   map[string]*ScanRecord
	sem     chan struct{}
	scanSeq int
}

// NewExecutor creates an Executor with the given concurrency limit.
func NewExecutor(maxWorkers int) Executor {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	return &executor{
		scans: make(map[string]*ScanRecord),
		sem:   make(chan struct{}, maxWorkers),
	}
}

// Submit queues a new scan and returns the record immediately.
func (e *executor) Submit(req ScanRequest) *ScanRecord {
	e.mu.Lock()
	e.scanSeq++
	scanID := fmt.Sprintf("scan-%d-%d", time.Now().UnixMilli(), e.scanSeq)
	rec := &ScanRecord{
		ScanID:  scanID,
		Status:  StatusQueued,
		Request: req,
	}
	e.scans[scanID] = rec
	e.mu.Unlock()

	go e.run(rec)
	return rec
}

// Get retrieves a scan record by ID.
func (e *executor) Get(scanID string) (*ScanRecord, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rec, ok := e.scans[scanID]
	return rec, ok
}

// List returns all scan records.
func (e *executor) List() []*ScanRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*ScanRecord, 0, len(e.scans))
	for _, rec := range e.scans {
		out = append(out, rec)
	}
	return out
}

// run executes the full ARGUS pipeline for a single scan.
func (e *executor) run(rec *ScanRecord) {
	// Acquire semaphore slot.
	e.sem <- struct{}{}
	defer func() { <-e.sem }()

	now := time.Now().UTC()
	e.mu.Lock()
	rec.Status = StatusRunning
	rec.StartedAt = &now
	e.mu.Unlock()

	result, err := e.executePipeline(rec.Request)

	e.mu.Lock()
	defer e.mu.Unlock()
	completed := time.Now().UTC()
	rec.CompletedAt = &completed
	if err != nil {
		rec.Status = StatusFailed
		rec.Error = err.Error()
	} else {
		rec.Status = StatusCompleted
		rec.Result = result
	}
}

// executePipeline mirrors the scan pipeline from cmd/scan.go:
// collector -> OPA evaluate -> enrich -> correlate -> score.
func (e *executor) executePipeline(req ScanRequest) (*ScanResult, error) {
	ctx := context.Background()

	// 1. Authenticate + collect.
	collector, err := azure.NewCollector(req.SubscriptionID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("azure collector init: %w", err)
	}
	snapshot, err := collector.CollectAll(ctx)
	if err != nil && snapshot == nil {
		return nil, fmt.Errorf("resource collection failed: %w", err)
	}
	if snapshot == nil {
		snapshot = &models.AzureSnapshot{
			SubscriptionID: req.SubscriptionID,
			TenantID:       req.TenantID,
			ScanTime:        time.Now().UTC(),
			CollectionMode:  "minimal",
		}
	}

	// 2. Evaluate policies via OPA.
	compliance := req.Compliance
	if compliance == "" {
		compliance = "all"
	}
	loader, err := benchmark.NewBenchmarkLoader()
	if err != nil {
		return nil, fmt.Errorf("benchmark loader: %w", err)
	}
	opaEngine, err := engine.NewOPAEngine()
	if err != nil {
		return nil, fmt.Errorf("OPA engine init: %w", err)
	}
	findings, err := opaEngine.Evaluate(snapshot, compliance)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation: %w", err)
	}
	for i := range findings {
		benchmark.EnrichFinding(&findings[i], loader)
	}

	// 3. Correlate attack chains.
	correlator := engine.NewCorrelator()
	chains := correlator.Correlate(findings, snapshot)
	correlator.MarkChainParticipants(findings, chains)

	// 4. Score.
	scoreReport := scorer.NewScorer().Score(findings, chains, snapshot)

	// Build a lightweight JSON-serialisable report for the full_report field.
	fullReport := map[string]any{
		"subscription_id": snapshot.SubscriptionID,
		"tenant_id":       snapshot.TenantID,
		"scan_time":       snapshot.ScanTime,
		"score":           scoreReport,
		"findings_count":  len(findings),
		"chains_count":    len(chains),
		"findings":        findings,
		"chains":          chains,
	}

	return &ScanResult{
		Score:         scoreReport.OverallScore,
		Grade:         scoreReport.Grade,
		FindingsCount: len(findings),
		ChainsCount:   len(chains),
		FullReport:    fullReport,
	}, nil
}
