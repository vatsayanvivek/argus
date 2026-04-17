package trend

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// ScanRecord is one historical snapshot of an ARGUS scan, persisted
// to disk for trend analysis. Records are append-only and never
// overwritten once written.
type ScanRecord struct {
	ScanID           string             `json:"scan_id"`
	ScanTime         time.Time          `json:"scan_time"`
	Subscription     string             `json:"subscription"`
	SubscriptionName string             `json:"subscription_name"`
	OverallScore     float64            `json:"overall_score"`
	Grade            string             `json:"grade"`
	PillarScores     map[string]float64 `json:"pillar_scores"`
	FindingIDs       []string           `json:"finding_ids"`
	ChainIDs         []string           `json:"chain_ids"`
	TotalFindings    int                `json:"total_findings"`
	ChainCount       int                `json:"chain_count"`
	CriticalCount    int                `json:"critical_count"`
	HighCount        int                `json:"high_count"`
}

// TrendReport compares a current scan to the most recent prior scan
// for the same subscription.
type TrendReport struct {
	HasPrevious      bool        `json:"has_previous"`
	CurrentScan      ScanRecord  `json:"current_scan"`
	PreviousScan     *ScanRecord `json:"previous_scan,omitempty"`
	ScoreDelta       float64     `json:"score_delta"`
	GradeChanged     bool        `json:"grade_changed"`
	NewFindings      []string    `json:"new_findings"`
	ResolvedFindings []string    `json:"resolved_findings"`
	NewChains        []string    `json:"new_chains"`
	ResolvedChains   []string    `json:"resolved_chains"`
	NewCritical      []string    `json:"new_critical"`
	Trend            string      `json:"trend"` // IMPROVING | DEGRADING | STABLE
	DaysSincePrev    int         `json:"days_since_prev"`
}

// historyDir returns the per-subscription history directory under
// ~/.argus/history/. If the home directory cannot be resolved it
// falls back to /tmp.
func historyDir(subscriptionID string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	safe := strings.ReplaceAll(subscriptionID, string(filepath.Separator), "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	return filepath.Join(home, ".argus", "history", safe), nil
}

// historyFile returns the scans.jsonl path for a subscription.
func historyFile(subscriptionID string) (string, error) {
	dir, err := historyDir(subscriptionID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "scans.jsonl"), nil
}

// SaveScanRecord appends a record to ~/.argus/history/<sub>/scans.jsonl.
// Rotates the file when it exceeds 10MB.
//
// NOTE: retained for backward compatibility with existing callers
// and tests. New code should prefer HistoryStore.Save.
func SaveScanRecord(record ScanRecord) error {
	if record.Subscription == "" {
		return errors.New("scan record has no subscription")
	}
	dir, err := historyDir(record.Subscription)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}
	path, err := historyFile(record.Subscription)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Rotate AFTER writing if > 10MB
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > 10*1024*1024 {
		rotated := path + ".1"
		_ = os.Remove(rotated)
		_ = os.Rename(path, rotated)
	}
	return nil
}

// LoadPreviousScan reads the most recent scan record from history.
// Returns (nil, nil) if no history exists yet.
//
// NOTE: retained for backward compatibility. New code should prefer
// HistoryStore.LoadPrevious.
func LoadPreviousScan(subscriptionID string) (*ScanRecord, error) {
	path, err := historyFile(subscriptionID)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open history: %w", err)
	}
	defer f.Close()

	// Read all lines (file is small) and return the last
	var lines [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		b := append([]byte{}, scanner.Bytes()...)
		if len(b) > 0 {
			lines = append(lines, b)
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("scan history: %w", err)
	}
	if len(lines) == 0 {
		return nil, nil
	}
	var rec ScanRecord
	if err := json.Unmarshal(lines[len(lines)-1], &rec); err != nil {
		return nil, fmt.Errorf("unmarshal last record: %w", err)
	}
	return &rec, nil
}

// LoadHistory returns all scan records for a subscription, oldest first.
// Optionally filtered to the last N days (pass 0 for all records).
func LoadHistory(subscriptionID string, days int) ([]ScanRecord, error) {
	path, err := historyFile(subscriptionID)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var records []ScanRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	cutoff := time.Now().AddDate(0, 0, -days)
	for scanner.Scan() {
		var r ScanRecord
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		if days > 0 && r.ScanTime.Before(cutoff) {
			continue
		}
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ScanTime.Before(records[j].ScanTime)
	})
	return records, nil
}

// HistoryStore is the on-disk store for scan records, keyed by
// subscription ID. Records live at:
//
//	~/.argus/history/<sub_id>/scans.jsonl
//
// in JSON-Lines format (one ScanRecord per line, append-only).
type HistoryStore struct {
	rootDir string
}

// NewHistoryStore creates a store rooted at ~/.argus/history.
// If the home directory cannot be resolved it falls back to /tmp.
func NewHistoryStore() *HistoryStore {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/tmp"
	}
	return &HistoryStore{rootDir: filepath.Join(home, ".argus", "history")}
}

// subDir returns the store's on-disk directory for a subscription,
// with separators in the ID neutralized.
func (h *HistoryStore) subDir(subscriptionID string) string {
	safe := strings.ReplaceAll(subscriptionID, string(filepath.Separator), "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	return filepath.Join(h.rootDir, safe)
}

// filePath returns the scans.jsonl path for a subscription.
func (h *HistoryStore) filePath(subscriptionID string) string {
	return filepath.Join(h.subDir(subscriptionID), "scans.jsonl")
}

// Save appends a record to the subscription's history file.
// Rotates to scans.jsonl.1 if the file exceeds 10MB.
func (h *HistoryStore) Save(record ScanRecord) error {
	if record.Subscription == "" {
		return errors.New("scan record has no subscription")
	}
	dir := h.subDir(record.Subscription)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}
	path := h.filePath(record.Subscription)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	line, err := json.Marshal(record)
	if err != nil {
		f.Close()
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	// Rotate AFTER write if > 10MB: truncate any existing .1 and
	// rename the active file to scans.jsonl.1.
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > 10*1024*1024 {
		rotated := path + ".1"
		_ = os.Remove(rotated)
		_ = os.Rename(path, rotated)
	}
	return nil
}

// LoadAll returns every record for a subscription, oldest first.
func (h *HistoryStore) LoadAll(subscriptionID string) ([]ScanRecord, error) {
	path := h.filePath(subscriptionID)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open history: %w", err)
	}
	defer f.Close()

	var records []ScanRecord
	scanner := bufio.NewScanner(f)
	// bufio.MaxScanTokenSize (64KB) is sufficient for a ScanRecord line.
	for scanner.Scan() {
		var r ScanRecord
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		records = append(records, r)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("scan history: %w", err)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ScanTime.Before(records[j].ScanTime)
	})
	return records, nil
}

// LoadPrevious returns the most recent record for a subscription
// EXCLUDING the one with the given scan ID. Returns (nil, nil) if
// there is no prior scan (first scan).
func (h *HistoryStore) LoadPrevious(subscriptionID string, currentScanID string) (*ScanRecord, error) {
	records, err := h.LoadAll(subscriptionID)
	if err != nil {
		return nil, err
	}
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].ScanID != currentScanID {
			r := records[i]
			return &r, nil
		}
	}
	return nil, nil
}

// BuildScanRecord assembles a ScanRecord from live scan results.
// The ScanID is a UTC timestamp string so records sort naturally.
// FindingIDs and ChainIDs are deduplicated and sorted.
func BuildScanRecord(
	subscriptionID string,
	subscriptionName string,
	findings []models.Finding,
	chains []models.AttackChain,
	score *models.ZTScoreReport,
) ScanRecord {
	now := time.Now().UTC()
	rec := ScanRecord{
		ScanID:           now.Format("20060102T150405Z"),
		ScanTime:         now,
		Subscription:     subscriptionID,
		SubscriptionName: subscriptionName,
		TotalFindings:    len(findings),
		ChainCount:       len(chains),
		PillarScores:     map[string]float64{},
	}
	if score != nil {
		rec.OverallScore = score.OverallScore
		rec.Grade = score.Grade
		for name, p := range score.PillarScores {
			rec.PillarScores[name] = p.Score
		}
		rec.CriticalCount = score.FindingsBySeverity["CRITICAL"]
		rec.HighCount = score.FindingsBySeverity["HIGH"]
	}

	findingSet := map[string]bool{}
	for _, f := range findings {
		key := fmt.Sprintf("%s::%s", f.ID, f.ResourceID)
		findingSet[key] = true
	}
	rec.FindingIDs = make([]string, 0, len(findingSet))
	for k := range findingSet {
		rec.FindingIDs = append(rec.FindingIDs, k)
	}
	sort.Strings(rec.FindingIDs)

	chainSet := map[string]bool{}
	for _, c := range chains {
		chainSet[c.ID] = true
	}
	rec.ChainIDs = make([]string, 0, len(chainSet))
	for k := range chainSet {
		rec.ChainIDs = append(rec.ChainIDs, k)
	}
	sort.Strings(rec.ChainIDs)

	return rec
}

// ComputeTrend produces a TrendReport given current and previous scans.
//
// Returns nil if previous is nil (no history). This preserves the
// long-standing behavior that callers use as a "first scan?" check.
// New code that wants a populated-but-empty report on first scan
// should call ComputeTrendDetailed with a nil previous instead.
func ComputeTrend(current ScanRecord, previous *ScanRecord) *TrendReport {
	if previous == nil {
		return nil
	}
	return computeTrendCore(current, previous, nil)
}

// ComputeTrendDetailed includes the live findings list so NewCritical
// can be filtered by actual severity. When previous is nil the report
// has HasPrevious=false, Trend="STABLE", and only the current snapshot.
func ComputeTrendDetailed(
	current ScanRecord,
	previous *ScanRecord,
	findings []models.Finding,
) *TrendReport {
	if previous == nil {
		return &TrendReport{
			HasPrevious: false,
			CurrentScan: current,
			Trend:       "STABLE",
		}
	}
	return computeTrendCore(current, previous, findings)
}

// computeTrendCore is the shared diff engine used by both ComputeTrend
// and ComputeTrendDetailed.
func computeTrendCore(
	current ScanRecord,
	previous *ScanRecord,
	findings []models.Finding,
) *TrendReport {
	tr := &TrendReport{
		HasPrevious:  true,
		CurrentScan:  current,
		PreviousScan: previous,
		ScoreDelta:   current.OverallScore - previous.OverallScore,
		GradeChanged: current.Grade != previous.Grade,
	}

	tr.NewFindings = setDifference(current.FindingIDs, previous.FindingIDs)
	tr.ResolvedFindings = setDifference(previous.FindingIDs, current.FindingIDs)
	tr.NewChains = setDifference(current.ChainIDs, previous.ChainIDs)
	tr.ResolvedChains = setDifference(previous.ChainIDs, current.ChainIDs)

	// NewCritical: if a live findings list was provided, filter
	// NewFindings down to those whose severity is CRITICAL. We match
	// on the same "<id>::<resource_id>" key used in BuildScanRecord.
	if findings != nil && len(tr.NewFindings) > 0 {
		critSet := map[string]bool{}
		for _, f := range findings {
			if strings.EqualFold(f.Severity, "CRITICAL") {
				critSet[fmt.Sprintf("%s::%s", f.ID, f.ResourceID)] = true
			}
		}
		newCrit := make([]string, 0)
		for _, id := range tr.NewFindings {
			if critSet[id] {
				newCrit = append(newCrit, id)
			}
		}
		tr.NewCritical = newCrit
	}

	// Days since previous
	tr.DaysSincePrev = int(current.ScanTime.Sub(previous.ScanTime).Hours() / 24)

	switch {
	case tr.ScoreDelta > 2.0:
		tr.Trend = "IMPROVING"
	case tr.ScoreDelta < -2.0:
		tr.Trend = "DEGRADING"
	default:
		tr.Trend = "STABLE"
	}
	return tr
}

// setDifference returns the elements of a that are not in b, sorted.
func setDifference(a, b []string) []string {
	bSet := make(map[string]bool, len(b))
	for _, x := range b {
		bSet[x] = true
	}
	out := make([]string, 0)
	for _, x := range a {
		if !bSet[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
