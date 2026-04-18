// Package server implements `argus serve`, a local-only HTTP dashboard.
//
// Design constraints (non-negotiable):
//
//   - Binds to loopback by default (127.0.0.1).
//   - No external network calls — every asset is embedded.
//   - No telemetry, no analytics, no tracking pixels.
//   - Reads scan data from disk, never phones home.
//
// The server exposes a tiny JSON API and a single-page HTML UI. Endpoints:
//
//   GET  /                  → index.html
//   GET  /static/*          → CSS / JS assets (embedded)
//   GET  /api/scans         → list of every scan file in the scan dir
//   GET  /api/scan/{id}     → a single scan's JSON
//   GET  /api/chains        → every chain the correlator registers (for the catalog)
//   GET  /api/rules         → every loaded Rego rule + metadata
//   GET  /api/diff/{a}/{b}  → drift between two scans
//   POST /api/scan          → trigger a background scan
//   GET  /api/scan/status   → status of the most recent triggered scan
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/models"
)

//go:embed web
var webFS embed.FS

// Config holds server tuning knobs.
type Config struct {
	Addr    string
	ScanDir string
}

// Server is the argus serve HTTP server.
type Server struct {
	cfg Config

	mu           sync.RWMutex
	scanStatus   scanRunStatus
	activeScanID string
}

type scanRunStatus struct {
	Running  bool      `json:"running"`
	StartedAt time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Error     string    `json:"error,omitempty"`
	ScanID    string    `json:"scan_id,omitempty"`
}

// New constructs a server configured to listen on cfg.Addr.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	if cfg.ScanDir == "" {
		cfg.ScanDir = "./argus-output"
	}
	return &Server{cfg: cfg}, nil
}

// Run installs every handler and blocks serving traffic.
func (s *Server) Run() error {
	mux := http.NewServeMux()

	// Static files — HTML / JS / CSS baked into the binary.
	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		return fmt.Errorf("web embed: %w", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(webSub))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s.serveFile(w, webSub, "index.html", "text/html; charset=utf-8")
	})

	// JSON API.
	mux.HandleFunc("/api/scans", s.handleListScans)
	mux.HandleFunc("/api/scan/", s.handleGetScan)
	mux.HandleFunc("/api/chains", s.handleChains)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/diff/", s.handleDiff)
	mux.HandleFunc("/api/scan-status", s.handleScanStatus)
	mux.HandleFunc("/api/trigger-scan", s.handleTriggerScan)

	fmt.Printf("ARGUS dashboard listening on http://%s\n", s.cfg.Addr)
	fmt.Printf("  scan-dir: %s\n", absPath(s.cfg.ScanDir))
	fmt.Println("  Press Ctrl+C to stop.")
	return http.ListenAndServe(s.cfg.Addr, mux)
}

func (s *Server) serveFile(w http.ResponseWriter, root fs.FS, name, contentType string) {
	raw, err := fs.ReadFile(root, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(raw)
}

// -----------------------------------------------------------------------------
// Scan listing + retrieval
// -----------------------------------------------------------------------------

type scanSummary struct {
	ID             string    `json:"id"`
	Filename       string    `json:"filename"`
	ScanTime       time.Time `json:"scan_time"`
	SubscriptionID string    `json:"subscription_id,omitempty"`
	TenantID       string    `json:"tenant_id,omitempty"`
	Critical       int       `json:"critical"`
	High           int       `json:"high"`
	Medium         int       `json:"medium"`
	Low            int       `json:"low"`
	ChainsCount    int       `json:"chains_count"`
	FindingsCount  int       `json:"findings_count"`
	SizeBytes      int64     `json:"size_bytes"`
}

type scanPayload struct {
	SubscriptionID string                 `json:"subscription_id"`
	TenantID       string                 `json:"tenant_id"`
	ScanTime       time.Time              `json:"scan_time"`
	Findings       []models.Finding       `json:"findings"`
	Chains         []models.AttackChain   `json:"chains"`
	Summary        map[string]interface{} `json:"summary,omitempty"`
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	files, err := listScanFiles(s.cfg.ScanDir)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]scanSummary, 0, len(files))
	for _, f := range files {
		sum, err := summariseScan(f)
		if err == nil {
			out = append(out, sum)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScanTime.After(out[j].ScanTime) })
	writeJSON(w, out)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	if id == "" || strings.Contains(id, "/") || strings.Contains(id, "..") {
		http.Error(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	// Allow either the filename or a short form.
	path := resolveScanPath(s.cfg.ScanDir, id)
	if path == "" {
		http.NotFound(w, r)
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// -----------------------------------------------------------------------------
// Catalog endpoints
// -----------------------------------------------------------------------------

func (s *Server) handleChains(w http.ResponseWriter, r *http.Request) {
	chains := engine.NewCorrelator().ExampleChains()
	sort.Slice(chains, func(i, j int) bool { return chains[i].ID < chains[j].ID })
	writeJSON(w, chains)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	eng, err := engine.NewOPAEngine()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	meta := eng.PolicyMetadata()
	out := make([]engine.PolicyMetadata, 0, len(meta))
	for _, m := range meta {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, out)
}

// -----------------------------------------------------------------------------
// Drift / diff
// -----------------------------------------------------------------------------

type diffResult struct {
	From            string        `json:"from"`
	To              string        `json:"to"`
	AddedFindings   []findingDiff `json:"added_findings"`
	ResolvedFindings []findingDiff `json:"resolved_findings"`
	AddedChains     []string      `json:"added_chains"`
	ResolvedChains  []string      `json:"resolved_chains"`
}

type findingDiff struct {
	ID           string `json:"id"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/diff/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "usage: /api/diff/<from-id>/<to-id>", http.StatusBadRequest)
		return
	}
	fromPath := resolveScanPath(s.cfg.ScanDir, parts[0])
	toPath := resolveScanPath(s.cfg.ScanDir, parts[1])
	if fromPath == "" || toPath == "" {
		http.NotFound(w, r)
		return
	}
	from, err := readScan(fromPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	to, err := readScan(toPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, computeDiff(parts[0], parts[1], from, to))
}

func computeDiff(fromID, toID string, from, to *scanPayload) diffResult {
	// Finding key = rule id + resource id.
	fromFindings := map[string]models.Finding{}
	toFindings := map[string]models.Finding{}
	for _, f := range from.Findings {
		fromFindings[f.ID+"|"+f.ResourceID] = f
	}
	for _, f := range to.Findings {
		toFindings[f.ID+"|"+f.ResourceID] = f
	}
	added := []findingDiff{}
	resolved := []findingDiff{}
	for k, f := range toFindings {
		if _, ok := fromFindings[k]; !ok {
			added = append(added, findingToDiff(f))
		}
	}
	for k, f := range fromFindings {
		if _, ok := toFindings[k]; !ok {
			resolved = append(resolved, findingToDiff(f))
		}
	}
	sort.Slice(added, func(i, j int) bool { return severityRank(added[i].Severity) < severityRank(added[j].Severity) })
	sort.Slice(resolved, func(i, j int) bool { return severityRank(resolved[i].Severity) < severityRank(resolved[j].Severity) })

	fromChains := map[string]bool{}
	toChains := map[string]bool{}
	for _, c := range from.Chains {
		fromChains[c.ID] = true
	}
	for _, c := range to.Chains {
		toChains[c.ID] = true
	}
	addedChains, resolvedChains := []string{}, []string{}
	for id := range toChains {
		if !fromChains[id] {
			addedChains = append(addedChains, id)
		}
	}
	for id := range fromChains {
		if !toChains[id] {
			resolvedChains = append(resolvedChains, id)
		}
	}
	sort.Strings(addedChains)
	sort.Strings(resolvedChains)

	return diffResult{
		From: fromID, To: toID,
		AddedFindings: added, ResolvedFindings: resolved,
		AddedChains: addedChains, ResolvedChains: resolvedChains,
	}
}

func findingToDiff(f models.Finding) findingDiff {
	return findingDiff{ID: f.ID, ResourceID: f.ResourceID, ResourceName: f.ResourceName, Severity: f.Severity, Title: f.Title}
}

// -----------------------------------------------------------------------------
// Trigger scan (background)
// -----------------------------------------------------------------------------

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, s.scanStatus)
}

type triggerScanRequest struct {
	Subscription string `json:"subscription"`
	Tenant       string `json:"tenant"`
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req triggerScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Subscription == "" || req.Tenant == "" {
		http.Error(w, "subscription and tenant are required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.scanStatus.Running {
		s.mu.Unlock()
		writeJSONError(w, http.StatusConflict, "a scan is already running")
		return
	}
	s.scanStatus = scanRunStatus{Running: true, StartedAt: time.Now().UTC()}
	s.mu.Unlock()

	go s.runBackgroundScan(req.Subscription, req.Tenant)
	writeJSON(w, map[string]string{"status": "started"})
}

func (s *Server) runBackgroundScan(subscription, tenant string) {
	// Discover the argus binary that's serving us.
	exe, err := os.Executable()
	if err != nil {
		s.setScanDone(1, fmt.Sprintf("cannot locate argus binary: %v", err))
		return
	}
	cmd := exec.Command(exe, "scan",
		"--subscription", subscription,
		"--tenant", tenant,
		"--output-dir", s.cfg.ScanDir,
		"--output", "json",
	)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	code := 0
	msg := ""
	if err != nil {
		code = 1
		msg = err.Error()
	}
	s.setScanDone(code, msg)
}

func (s *Server) setScanDone(code int, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanStatus.Running = false
	s.scanStatus.FinishedAt = time.Now().UTC()
	s.scanStatus.ExitCode = code
	s.scanStatus.Error = errMsg
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func listScanFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "argus_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out, nil
}

func resolveScanPath(dir, id string) string {
	// id may be the scan filename (argus_20260418_102231.json) or the
	// sans-extension form.
	if strings.HasSuffix(id, ".json") {
		p := filepath.Join(dir, id)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	candidate := filepath.Join(dir, id+".json")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	candidate = filepath.Join(dir, id)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func readScan(path string) (*scanPayload, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p scanPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func summariseScan(path string) (scanSummary, error) {
	info, err := os.Stat(path)
	if err != nil {
		return scanSummary{}, err
	}
	p, err := readScan(path)
	if err != nil {
		return scanSummary{}, err
	}
	sum := scanSummary{
		ID:             strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		Filename:       filepath.Base(path),
		ScanTime:       p.ScanTime,
		SubscriptionID: p.SubscriptionID,
		TenantID:       p.TenantID,
		SizeBytes:      info.Size(),
		FindingsCount:  len(p.Findings),
		ChainsCount:    len(p.Chains),
	}
	if sum.ScanTime.IsZero() {
		sum.ScanTime = info.ModTime()
	}
	for _, f := range p.Findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			sum.Critical++
		case "HIGH":
			sum.High++
		case "MEDIUM":
			sum.Medium++
		case "LOW":
			sum.Low++
		}
	}
	return sum, nil
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

func writeJSON(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

// Silence unused-imports hints when iterating.
var _ = log.Println
