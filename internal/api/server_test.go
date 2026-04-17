package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockExecutor is a test double that avoids Azure credentials.
type mockExecutor struct {
	scans map[string]*ScanRecord
	seq   int
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{scans: make(map[string]*ScanRecord)}
}

func (m *mockExecutor) Submit(req ScanRequest) *ScanRecord {
	m.seq++
	now := time.Now().UTC()
	completed := now.Add(1 * time.Second)
	rec := &ScanRecord{
		ScanID:      "mock-scan-1",
		Status:      StatusCompleted,
		Request:     req,
		StartedAt:   &now,
		CompletedAt: &completed,
		Result: &ScanResult{
			Score:         72.5,
			Grade:         "B",
			FindingsCount: 15,
			ChainsCount:   3,
			FullReport: map[string]any{
				"subscription_id": req.SubscriptionID,
				"findings_count":  15,
				"chains_count":    3,
			},
		},
	}
	m.scans[rec.ScanID] = rec
	return rec
}

func (m *mockExecutor) Get(scanID string) (*ScanRecord, bool) {
	rec, ok := m.scans[scanID]
	return rec, ok
}

func (m *mockExecutor) List() []*ScanRecord {
	out := make([]*ScanRecord, 0, len(m.scans))
	for _, rec := range m.scans {
		out = append(out, rec)
	}
	return out
}

// helper to create a test server with the given auth key.
func newTestServer(authKey string) (*Server, *mockExecutor) {
	exec := newMockExecutor()
	srv := NewServer(0, authKey, exec)
	return srv, exec
}

// helper to build a mux that mirrors the real server routing.
func buildTestMux(s *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/rules", s.withAuth(s.handleRules))
	mux.HandleFunc("POST /api/v1/scan", s.withAuth(s.handleSubmitScan))
	mux.HandleFunc("GET /api/v1/scans/", s.withAuth(s.handleScanRoutes))
	return mux
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer("")
	mux := buildTestMux(srv)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", resp["status"])
	}
}

func TestRulesEndpointReturnsRules(t *testing.T) {
	srv, _ := newTestServer("")
	mux := buildTestMux(srv)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Rules endpoint may fail if benchmark/OPA data files are missing
	// in the test environment. Accept either 200 with rules or 500.
	if w.Code == http.StatusOK {
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		count, ok := resp["count"].(float64)
		if !ok {
			t.Errorf("expected count field in response")
		}
		if count == 0 {
			t.Errorf("expected non-zero rule count")
		}
	} else if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 200 or 500, got %d", w.Code)
	}
}

func TestAuthKeyRequired(t *testing.T) {
	srv, _ := newTestServer("my-secret-key")
	mux := buildTestMux(srv)

	// Request without key should get 401.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without API key, got %d", w.Code)
	}

	// Request with wrong key should get 401.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong key, got %d", w.Code)
	}
}

func TestAuthKeyAccepted(t *testing.T) {
	srv, _ := newTestServer("my-secret-key")
	mux := buildTestMux(srv)

	body := `{"subscription_id":"sub-123","tenant_id":"tenant-456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", "my-secret-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 with valid key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScanSubmission(t *testing.T) {
	srv, _ := newTestServer("")
	mux := buildTestMux(srv)

	body := `{"subscription_id":"sub-123","tenant_id":"tenant-456","compliance":"all"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	scanID, ok := resp["scan_id"].(string)
	if !ok || scanID == "" {
		t.Error("expected non-empty scan_id")
	}
	if resp["status"] != "completed" {
		// The mock executor returns completed immediately.
		t.Errorf("expected status=completed from mock, got %v", resp["status"])
	}
}

func TestScanStatusEndpoint(t *testing.T) {
	srv, exec := newTestServer("")
	mux := buildTestMux(srv)

	// Pre-populate a scan via the mock.
	scanReq := ScanRequest{SubscriptionID: "sub-1", TenantID: "t-1"}
	exec.Submit(scanReq)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/mock-scan-1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["scan_id"] != "mock-scan-1" {
		t.Errorf("expected scan_id=mock-scan-1, got %v", resp["scan_id"])
	}
	if resp["status"] != "completed" {
		t.Errorf("expected status=completed, got %v", resp["status"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatal("expected result object in response")
	}
	if result["score"].(float64) != 72.5 {
		t.Errorf("expected score=72.5, got %v", result["score"])
	}
}

func TestScanReportEndpoint(t *testing.T) {
	srv, exec := newTestServer("")
	mux := buildTestMux(srv)

	exec.Submit(ScanRequest{SubscriptionID: "sub-1", TenantID: "t-1"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/mock-scan-1/report", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["subscription_id"] != "sub-1" {
		t.Errorf("expected subscription_id=sub-1, got %v", resp["subscription_id"])
	}
}

func TestScanNotFound(t *testing.T) {
	srv, _ := newTestServer("")
	mux := buildTestMux(srv)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/does-not-exist", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestScanValidation(t *testing.T) {
	srv, _ := newTestServer("")
	mux := buildTestMux(srv)

	// Missing subscription_id.
	body := `{"tenant_id":"t-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing subscription_id, got %d", w.Code)
	}

	// Missing tenant_id.
	body = `{"subscription_id":"s-1"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/scan", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing tenant_id, got %d", w.Code)
	}
}

func TestReportNotReadyWhileRunning(t *testing.T) {
	srv, exec := newTestServer("")
	mux := buildTestMux(srv)

	// Manually insert a running scan.
	now := time.Now().UTC()
	exec.scans["running-1"] = &ScanRecord{
		ScanID:    "running-1",
		Status:    StatusRunning,
		StartedAt: &now,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/running-1/report", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for non-completed scan report, got %d", w.Code)
	}
}

func TestGracefulShutdown(t *testing.T) {
	exec := newMockExecutor()
	srv := NewServer(0, "", exec)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately to trigger shutdown.
	cancel()

	// ListenAndServe with port 0 will pick a random port. Since we
	// cancel immediately, it should shut down cleanly.
	err := srv.ListenAndServe(ctx)
	if err != nil {
		t.Fatalf("expected clean shutdown, got: %v", err)
	}
}
