package trend

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoadScanRecord(t *testing.T) {
	// Use a temp HOME to isolate from real ~/.argus
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	rec := ScanRecord{
		ScanID:        "test-001",
		ScanTime:      time.Now().UTC(),
		Subscription:  "sub-1",
		OverallScore:  75.5,
		Grade:         "B",
		FindingIDs:    []string{"zt_net_001::nsg1", "zt_id_011::app1"},
		ChainIDs:      []string{"CHAIN-001"},
		TotalFindings: 2,
		ChainCount:    1,
	}

	if err := SaveScanRecord(rec); err != nil {
		t.Fatalf("SaveScanRecord: %v", err)
	}

	loaded, err := LoadPreviousScan("sub-1")
	if err != nil {
		t.Fatalf("LoadPreviousScan: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected loaded record, got nil")
	}
	if loaded.OverallScore != 75.5 {
		t.Errorf("expected score 75.5, got %.1f", loaded.OverallScore)
	}
	if len(loaded.FindingIDs) != 2 {
		t.Errorf("expected 2 finding ids, got %d", len(loaded.FindingIDs))
	}
}

func TestComputeTrend_Improving(t *testing.T) {
	prev := &ScanRecord{
		ScanTime:     time.Now().Add(-24 * time.Hour),
		OverallScore: 60,
		Grade:        "C",
		FindingIDs:   []string{"a", "b", "c"},
		ChainIDs:     []string{"X", "Y"},
	}
	cur := ScanRecord{
		ScanTime:     time.Now(),
		OverallScore: 75,
		Grade:        "B",
		FindingIDs:   []string{"a", "d"},
		ChainIDs:     []string{"Z"},
	}

	tr := ComputeTrend(cur, prev)
	if tr == nil {
		t.Fatal("expected trend report")
	}
	if tr.Trend != "IMPROVING" {
		t.Errorf("expected IMPROVING, got %s", tr.Trend)
	}
	if tr.ScoreDelta != 15 {
		t.Errorf("expected delta 15, got %.1f", tr.ScoreDelta)
	}
	if !tr.GradeChanged {
		t.Error("grade should have changed")
	}
	// b and c are resolved
	if len(tr.ResolvedFindings) != 2 {
		t.Errorf("expected 2 resolved findings, got %d", len(tr.ResolvedFindings))
	}
	// d is new
	if len(tr.NewFindings) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(tr.NewFindings))
	}
}

func TestComputeTrend_NoPrevious(t *testing.T) {
	cur := ScanRecord{ScanTime: time.Now(), OverallScore: 80}
	tr := ComputeTrend(cur, nil)
	if tr != nil {
		t.Error("expected nil trend when no previous scan")
	}
}

func TestHistoryFileCreatedCorrectly(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	rec := ScanRecord{Subscription: "test-sub", ScanTime: time.Now()}
	if err := SaveScanRecord(rec); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(tmpHome, ".argus", "history", "test-sub", "scans.jsonl")
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("history file not created at %s: %v", expected, err)
	}
}
