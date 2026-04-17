package webhooks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Shared fixture
// ---------------------------------------------------------------------------

func sampleSummary() ScanSummary {
	return ScanSummary{
		SubscriptionID:   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		SubscriptionName: "production-core",
		TenantID:         "11111111-2222-3333-4444-555555555555",
		ScanTime:         "2026-04-12T10:30:00Z",
		OverallScore:     42.5,
		Grade:            "D",
		TotalFindings:    87,
		CriticalFindings: 12,
		HighFindings:     25,
		TotalChains:      6,
		CriticalChains:   3,
		TopChains: []ChainSummary{
			{ID: "CHAIN-001", Title: "Key Vault to Storage lateral move", Severity: "CRITICAL", Steps: 4},
			{ID: "CHAIN-002", Title: "Identity escalation via App Reg", Severity: "HIGH", Steps: 3},
		},
	}
}

// ---------------------------------------------------------------------------
// Payload format tests
// ---------------------------------------------------------------------------

func TestBuildJSONPayload(t *testing.T) {
	data, err := buildJSONPayload(sampleSummary())
	if err != nil {
		t.Fatalf("buildJSONPayload: %v", err)
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if envelope["event"] != "argus_scan" {
		t.Errorf("expected event=argus_scan, got %v", envelope["event"])
	}
	if envelope["version"] != "1.2" {
		t.Errorf("expected version=1.2, got %v", envelope["version"])
	}

	inner, ok := envelope["data"].(map[string]interface{})
	if !ok {
		t.Fatal("data field is not a map")
	}
	if inner["grade"] != "D" {
		t.Errorf("expected grade=D, got %v", inner["grade"])
	}
	if int(inner["total_findings"].(float64)) != 87 {
		t.Errorf("expected total_findings=87, got %v", inner["total_findings"])
	}
}

func TestBuildSlackPayload(t *testing.T) {
	data, err := buildSlackPayload(sampleSummary())
	if err != nil {
		t.Fatalf("buildSlackPayload: %v", err)
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	blocks, ok := msg["blocks"].([]interface{})
	if !ok || len(blocks) == 0 {
		t.Fatal("expected non-empty blocks array")
	}

	// First block should be a section with the header.
	first := blocks[0].(map[string]interface{})
	if first["type"] != "section" {
		t.Errorf("first block type: got %v, want section", first["type"])
	}

	// Should contain a divider somewhere.
	hasDivider := false
	for _, b := range blocks {
		if bm, ok := b.(map[string]interface{}); ok && bm["type"] == "divider" {
			hasDivider = true
			break
		}
	}
	if !hasDivider {
		t.Error("expected at least one divider block")
	}

	// Verify the raw JSON is valid and non-trivially sized (real Slack
	// payloads with Block Kit are at least a few hundred bytes).
	if len(data) < 200 {
		t.Errorf("payload suspiciously small: %d bytes", len(data))
	}
}

func TestBuildTeamsPayload(t *testing.T) {
	data, err := buildTeamsPayload(sampleSummary())
	if err != nil {
		t.Fatalf("buildTeamsPayload: %v", err)
	}

	var card map[string]interface{}
	if err := json.Unmarshal(data, &card); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if card["@type"] != "MessageCard" {
		t.Errorf("expected @type=MessageCard, got %v", card["@type"])
	}
	if card["themeColor"] != "cc0000" {
		t.Errorf("expected themeColor=cc0000 for grade D, got %v", card["themeColor"])
	}

	sections, ok := card["sections"].([]interface{})
	if !ok || len(sections) < 2 {
		t.Fatal("expected at least 2 sections (facts + chains)")
	}
}

// ---------------------------------------------------------------------------
// Event filtering tests
// ---------------------------------------------------------------------------

func TestShouldFire_OnComplete(t *testing.T) {
	s := ScanSummary{CriticalFindings: 0, TotalChains: 0}
	if !shouldFire(s, []string{"on-complete"}) {
		t.Error("on-complete should always fire")
	}
}

func TestShouldFire_EmptyEvents(t *testing.T) {
	s := ScanSummary{}
	if !shouldFire(s, nil) {
		t.Error("nil events should fire (default to on-complete)")
	}
	if !shouldFire(s, []string{}) {
		t.Error("empty events should fire (default to on-complete)")
	}
}

func TestShouldFire_OnCritical_WithCriticals(t *testing.T) {
	s := ScanSummary{CriticalFindings: 5}
	if !shouldFire(s, []string{"on-critical"}) {
		t.Error("on-critical should fire when CriticalFindings > 0")
	}
}

func TestShouldFire_OnCritical_NoCriticals(t *testing.T) {
	s := ScanSummary{CriticalFindings: 0}
	if shouldFire(s, []string{"on-critical"}) {
		t.Error("on-critical should NOT fire when CriticalFindings == 0")
	}
}

func TestShouldFire_OnChain_WithChains(t *testing.T) {
	s := ScanSummary{TotalChains: 3}
	if !shouldFire(s, []string{"on-chain"}) {
		t.Error("on-chain should fire when TotalChains > 0")
	}
}

func TestShouldFire_OnChain_NoChains(t *testing.T) {
	s := ScanSummary{TotalChains: 0}
	if shouldFire(s, []string{"on-chain"}) {
		t.Error("on-chain should NOT fire when TotalChains == 0")
	}
}

func TestShouldFire_MultipleEvents_OneMatches(t *testing.T) {
	s := ScanSummary{CriticalFindings: 0, TotalChains: 2}
	// on-critical won't match, but on-chain will.
	if !shouldFire(s, []string{"on-critical", "on-chain"}) {
		t.Error("should fire when at least one event matches")
	}
}

func TestShouldFire_MultipleEvents_NoneMatch(t *testing.T) {
	s := ScanSummary{CriticalFindings: 0, TotalChains: 0}
	if shouldFire(s, []string{"on-critical", "on-chain"}) {
		t.Error("should NOT fire when no events match")
	}
}

// ---------------------------------------------------------------------------
// HTTP delivery tests (httptest)
// ---------------------------------------------------------------------------

func TestSend_DeliversJSONToServer(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		received = body

		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type: got %q, want application/json", ct)
		}
		if ua := r.Header.Get("User-Agent"); ua != "ARGUS/1.2" {
			t.Errorf("User-Agent: got %q, want ARGUS/1.2", ua)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier()
	errs := n.Send(sampleSummary(), []WebhookConfig{
		{
			Name:   "test-json",
			URL:    srv.URL,
			Format: "json",
			Events: []string{"on-complete"},
		},
	})

	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("server received no body")
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(received, &envelope); err != nil {
		t.Fatalf("received body is not valid JSON: %v", err)
	}
	if envelope["event"] != "argus_scan" {
		t.Errorf("expected event=argus_scan in delivered payload")
	}
}

func TestSend_CustomHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Api-Key"); v != "secret-123" {
			t.Errorf("custom header X-Api-Key: got %q, want secret-123", v)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier()
	errs := n.Send(sampleSummary(), []WebhookConfig{
		{
			Name:    "test-headers",
			URL:     srv.URL,
			Format:  "json",
			Events:  []string{"on-complete"},
			Headers: map[string]string{"X-Api-Key": "secret-123"},
		},
	})

	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

func TestSend_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := NewNotifier()
	errs := n.Send(sampleSummary(), []WebhookConfig{
		{
			Name:   "test-fail",
			URL:    srv.URL,
			Format: "json",
			Events: []string{"on-complete"},
		},
	})

	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
}

func TestSend_SkippedByEventFilter(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Summary with zero criticals and zero chains.
	summary := ScanSummary{
		CriticalFindings: 0,
		TotalChains:      0,
	}

	n := NewNotifier()
	errs := n.Send(summary, []WebhookConfig{
		{
			Name:   "test-skip",
			URL:    srv.URL,
			Format: "json",
			Events: []string{"on-critical", "on-chain"},
		},
	})

	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if called {
		t.Error("webhook should NOT have been called — event filter should skip it")
	}
}

func TestSend_SlackFormat_DeliversValidJSON(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier()
	errs := n.Send(sampleSummary(), []WebhookConfig{
		{Name: "slack", URL: srv.URL, Format: "slack", Events: []string{"on-complete"}},
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(received, &msg); err != nil {
		t.Fatalf("Slack payload is not valid JSON: %v", err)
	}
	if _, ok := msg["blocks"]; !ok {
		t.Error("Slack payload missing 'blocks' key")
	}
}

func TestSend_TeamsFormat_DeliversValidJSON(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier()
	errs := n.Send(sampleSummary(), []WebhookConfig{
		{Name: "teams", URL: srv.URL, Format: "teams", Events: []string{"on-complete"}},
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	var card map[string]interface{}
	if err := json.Unmarshal(received, &card); err != nil {
		t.Fatalf("Teams payload is not valid JSON: %v", err)
	}
	if card["@type"] != "MessageCard" {
		t.Errorf("Teams payload @type: got %v, want MessageCard", card["@type"])
	}
}

func TestSend_MultipleWebhooks(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier()
	errs := n.Send(sampleSummary(), []WebhookConfig{
		{Name: "a", URL: srv.URL, Format: "json", Events: []string{"on-complete"}},
		{Name: "b", URL: srv.URL, Format: "slack", Events: []string{"on-complete"}},
		{Name: "c", URL: srv.URL, Format: "teams", Events: []string{"on-complete"}},
	})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	mu.Lock()
	defer mu.Unlock()
	if callCount != 3 {
		t.Errorf("expected 3 webhook calls, got %d", callCount)
	}
}
