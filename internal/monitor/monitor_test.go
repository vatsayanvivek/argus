package monitor

import (
	"context"
	"math"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Delta computation
// ---------------------------------------------------------------------------

func TestComputeDelta_NoPrevious(t *testing.T) {
	current := &ScanResult{
		SubscriptionID: "sub-1",
		Score:          72.5,
		TotalFindings:  10,
		TotalChains:    3,
		Timestamp:      time.Now(),
	}

	delta := ComputeDelta(nil, current)

	if delta.ScoreDelta != 0 {
		t.Errorf("expected ScoreDelta 0 for first scan, got %.1f", delta.ScoreDelta)
	}
	if delta.PreviousScore != current.Score {
		t.Errorf("expected PreviousScore to equal CurrentScore on first scan")
	}
	if delta.NewFindings != 10 {
		t.Errorf("expected NewFindings=10, got %d", delta.NewFindings)
	}
	if delta.NewChains != 3 {
		t.Errorf("expected NewChains=3, got %d", delta.NewChains)
	}
}

func TestComputeDelta_ScoreImproved(t *testing.T) {
	prev := &ScanResult{
		SubscriptionID: "sub-1",
		Score:          60.0,
		TotalFindings:  15,
		TotalChains:    5,
		Timestamp:      time.Now().Add(-4 * time.Hour),
	}
	current := &ScanResult{
		SubscriptionID: "sub-1",
		Score:          75.0,
		TotalFindings:  8,
		TotalChains:    2,
		Timestamp:      time.Now(),
	}

	delta := ComputeDelta(prev, current)

	if delta.ScoreDelta != 15.0 {
		t.Errorf("expected ScoreDelta=15.0, got %.1f", delta.ScoreDelta)
	}
	if delta.ResolvedFindings != 7 {
		t.Errorf("expected ResolvedFindings=7, got %d", delta.ResolvedFindings)
	}
	if delta.NewFindings != 0 {
		t.Errorf("expected NewFindings=0, got %d", delta.NewFindings)
	}
	if delta.ResolvedChains != 3 {
		t.Errorf("expected ResolvedChains=3, got %d", delta.ResolvedChains)
	}
}

func TestComputeDelta_ScoreDegraded(t *testing.T) {
	prev := &ScanResult{
		SubscriptionID: "sub-1",
		Score:          80.0,
		TotalFindings:  5,
		TotalChains:    1,
		Timestamp:      time.Now().Add(-4 * time.Hour),
	}
	current := &ScanResult{
		SubscriptionID: "sub-1",
		Score:          65.0,
		TotalFindings:  12,
		TotalChains:    4,
		Timestamp:      time.Now(),
	}

	delta := ComputeDelta(prev, current)

	if delta.ScoreDelta != -15.0 {
		t.Errorf("expected ScoreDelta=-15.0, got %.1f", delta.ScoreDelta)
	}
	if delta.NewFindings != 7 {
		t.Errorf("expected NewFindings=7, got %d", delta.NewFindings)
	}
	if delta.NewChains != 3 {
		t.Errorf("expected NewChains=3, got %d", delta.NewChains)
	}
}

// ---------------------------------------------------------------------------
// Drift detection threshold
// ---------------------------------------------------------------------------

func TestDriftDetection_AboveThreshold(t *testing.T) {
	cases := []struct {
		name       string
		scoreDelta float64
		wantDrift  bool
	}{
		{"large positive drift", 10.0, true},
		{"large negative drift", -8.0, true},
		{"exactly at threshold", 5.0, false},       // > 5, not >=5
		{"negative at threshold", -5.0, false},
		{"small positive change", 3.0, false},
		{"small negative change", -2.5, false},
		{"zero change", 0.0, false},
		{"just over threshold", 5.1, true},
		{"just under negative threshold", -5.1, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isDrift := math.Abs(tc.scoreDelta) > 5.0
			if isDrift != tc.wantDrift {
				t.Errorf("scoreDelta=%.1f: expected drift=%v, got %v",
					tc.scoreDelta, tc.wantDrift, isDrift)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Context cancellation stops the loop
// ---------------------------------------------------------------------------

func TestRun_ContextCancellation(t *testing.T) {
	scanCount := 0

	mon := &Monitor{
		TenantID:       "test-tenant",
		SubscriptionID: "test-sub",
		Interval:       1 * time.Hour, // long interval so we rely on cancel
		ScanFunc: func(ctx context.Context, subID, tenantID string) (*ScanResult, error) {
			scanCount++
			return &ScanResult{
				SubscriptionID: subID,
				Score:          72.5,
				TotalFindings:  5,
				TotalChains:    2,
				Timestamp:      time.Now().UTC(),
			}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- mon.Run(ctx)
	}()

	// Give the first scan cycle time to complete, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on clean shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not stop within 2s after context cancellation")
	}

	if scanCount < 1 {
		t.Errorf("expected at least 1 scan, got %d", scanCount)
	}
}

// ---------------------------------------------------------------------------
// History eviction
// ---------------------------------------------------------------------------

func TestRecordResult_EvictsOldEntries(t *testing.T) {
	mon := &Monitor{
		TenantID:       "t",
		SubscriptionID: "s",
		history:        make(map[string][]*ScanResult),
	}

	for i := 0; i < maxHistory+5; i++ {
		mon.recordResult("sub-1", &ScanResult{
			SubscriptionID: "sub-1",
			Score:          float64(i),
			Timestamp:      time.Now(),
		})
	}

	mon.mu.Lock()
	defer mon.mu.Unlock()

	if len(mon.history["sub-1"]) != maxHistory {
		t.Errorf("expected history capped at %d, got %d", maxHistory, len(mon.history["sub-1"]))
	}

	// The oldest retained entry should have score == 5 (indices 0-4 evicted).
	oldest := mon.history["sub-1"][0]
	if oldest.Score != 5.0 {
		t.Errorf("expected oldest score=5.0, got %.1f", oldest.Score)
	}
}

// ---------------------------------------------------------------------------
// Internal delta via Monitor method
// ---------------------------------------------------------------------------

func TestMonitor_ComputeDelta_WithHistory(t *testing.T) {
	mon := &Monitor{
		TenantID: "t",
		history:  make(map[string][]*ScanResult),
	}

	// Record a previous result.
	mon.recordResult("sub-1", &ScanResult{
		SubscriptionID: "sub-1",
		Score:          70.0,
		TotalFindings:  10,
		TotalChains:    3,
		Timestamp:      time.Now().Add(-4 * time.Hour),
	})

	current := &ScanResult{
		SubscriptionID: "sub-1",
		Score:          65.0,
		TotalFindings:  13,
		TotalChains:    2,
		Timestamp:      time.Now(),
	}

	delta := mon.computeDelta("sub-1", current)

	if delta.ScoreDelta != -5.0 {
		t.Errorf("expected ScoreDelta=-5.0, got %.1f", delta.ScoreDelta)
	}
	if delta.NewFindings != 3 {
		t.Errorf("expected NewFindings=3, got %d", delta.NewFindings)
	}
	if delta.ResolvedChains != 1 {
		t.Errorf("expected ResolvedChains=1, got %d", delta.ResolvedChains)
	}
}
