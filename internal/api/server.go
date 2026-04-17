package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vatsayanvivek/argus/internal/benchmark"
	"github.com/vatsayanvivek/argus/internal/engine"
)

// Server is the ARGUS HTTP API server.
type Server struct {
	port     int
	authKey  string
	executor Executor
	srv      *http.Server
}

// NewServer creates a new API server.
func NewServer(port int, authKey string, executor Executor) *Server {
	return &Server{
		port:     port,
		authKey:  authKey,
		executor: executor,
	}
}

// ListenAndServe starts the HTTP server. It blocks until the server shuts down.
func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()

	// Register routes.
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/rules", s.withAuth(s.handleRules))
	mux.HandleFunc("POST /api/v1/scan", s.withAuth(s.handleSubmitScan))
	mux.HandleFunc("GET /api/v1/scans/", s.withAuth(s.handleScanRoutes))

	s.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on context cancellation.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("server shutdown error: %v", err)
		}
	}()

	log.Printf("ARGUS API server listening on :%d", s.port)
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// withAuth wraps a handler with API key validation when an auth key is configured.
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authKey != "" {
			key := r.Header.Get("X-API-Key")
			if key != s.authKey {
				writeError(w, http.StatusUnauthorized, "missing or invalid API key")
				return
			}
		}
		next(w, r)
	}
}

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "healthy",
		"version": "1.2.0",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// handleRules lists all loaded CIS and ZT policies.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	type ruleEntry struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity string `json:"severity,omitempty"`
		Pillar   string `json:"pillar,omitempty"`
		Source   string `json:"source"` // cis | zt
	}

	var rules []ruleEntry

	// CIS rules from benchmark loader.
	loader, err := benchmark.NewBenchmarkLoader()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load benchmark data: %v", err))
		return
	}
	for id, rule := range loader.CISRules {
		rules = append(rules, ruleEntry{
			ID:     id,
			Title:  rule.Title,
			Source: "cis",
		})
	}

	// ZT rules from OPA metadata.
	opaEngine, err := engine.NewOPAEngine()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load OPA engine: %v", err))
		return
	}
	for id, meta := range opaEngine.PolicyMetadata() {
		if strings.HasPrefix(id, "zt_") {
			rules = append(rules, ruleEntry{
				ID:       id,
				Title:    meta.Title,
				Severity: meta.Severity,
				Pillar:   meta.Pillar,
				Source:   "zt",
			})
		}
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(rules),
		"rules": rules,
	})
}

// handleSubmitScan accepts a scan request and queues it for execution.
func (s *Server) handleSubmitScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	if req.SubscriptionID == "" {
		writeError(w, http.StatusBadRequest, "subscription_id is required")
		return
	}
	if req.TenantID == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.Compliance == "" {
		req.Compliance = "all"
	}

	rec := s.executor.Submit(req)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"scan_id": rec.ScanID,
		"status":  rec.Status,
	})
}

// handleScanRoutes dispatches /api/v1/scans/{scan_id}[/report] routes.
func (s *Server) handleScanRoutes(w http.ResponseWriter, r *http.Request) {
	// Parse the scan ID and optional trailing segment from the path.
	// Path format: /api/v1/scans/{scan_id} or /api/v1/scans/{scan_id}/report
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.SplitN(path, "/", 2)
	scanID := parts[0]
	if scanID == "" {
		writeError(w, http.StatusBadRequest, "scan_id is required in path")
		return
	}

	rec, ok := s.executor.Get(scanID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("scan %q not found", scanID))
		return
	}

	// /api/v1/scans/{scan_id}/report
	if len(parts) == 2 && parts[1] == "report" {
		s.handleScanReport(w, rec)
		return
	}

	// /api/v1/scans/{scan_id}
	s.handleScanStatus(w, rec)
}

// handleScanStatus returns the status of a scan.
func (s *Server) handleScanStatus(w http.ResponseWriter, rec *ScanRecord) {
	resp := map[string]any{
		"scan_id": rec.ScanID,
		"status":  rec.Status,
	}
	if rec.StartedAt != nil {
		resp["started_at"] = rec.StartedAt.Format(time.RFC3339)
	}
	if rec.CompletedAt != nil {
		resp["completed_at"] = rec.CompletedAt.Format(time.RFC3339)
	}
	if rec.Status == StatusCompleted && rec.Result != nil {
		resp["result"] = map[string]any{
			"score":          rec.Result.Score,
			"grade":          rec.Result.Grade,
			"findings_count": rec.Result.FindingsCount,
			"chains_count":   rec.Result.ChainsCount,
		}
	}
	if rec.Status == StatusFailed && rec.Error != "" {
		resp["error"] = rec.Error
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleScanReport returns the full JSON report for a completed scan.
func (s *Server) handleScanReport(w http.ResponseWriter, rec *ScanRecord) {
	if rec.Status != StatusCompleted {
		writeError(w, http.StatusConflict, fmt.Sprintf("scan is %s, report only available when completed", rec.Status))
		return
	}
	if rec.Result == nil || rec.Result.FullReport == nil {
		writeError(w, http.StatusInternalServerError, "report data is missing")
		return
	}
	writeJSON(w, http.StatusOK, rec.Result.FullReport)
}

// writeJSON serialises v as JSON and writes it to the response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeError writes a structured JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error":  http.StatusText(status),
		"detail": message,
	})
}
