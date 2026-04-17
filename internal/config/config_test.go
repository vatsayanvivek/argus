package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Defaults.Compliance != "cis" {
		t.Errorf("expected default compliance 'cis', got %q", cfg.Defaults.Compliance)
	}
	if cfg.Defaults.Output != "json" {
		t.Errorf("expected default output 'json', got %q", cfg.Defaults.Output)
	}
	if cfg.APIServer.Port != 8443 {
		t.Errorf("expected default port 8443, got %d", cfg.APIServer.Port)
	}
	if cfg.APIServer.Workers != 4 {
		t.Errorf("expected default workers 4, got %d", cfg.APIServer.Workers)
	}
	if cfg.CIGates.ExitCodeOnFail != 2 {
		t.Errorf("expected default exit_code_on_fail 2, got %d", cfg.CIGates.ExitCodeOnFail)
	}
	if !cfg.CIGates.FailOnCritical {
		t.Error("expected default fail_on_critical true")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return zero-value config.
	if cfg.Defaults.Compliance != "" {
		t.Errorf("expected empty compliance, got %q", cfg.Defaults.Compliance)
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "argus.yaml")

	content := `
defaults:
  tenant_id: "test-tenant"
  compliance: "zt"
  output: "html"
  drift: true
ci_gates:
  enabled: true
  fail_on_critical: true
  critical_threshold: 3
api_server:
  port: 9090
  workers: 8
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Defaults.TenantID != "test-tenant" {
		t.Errorf("expected tenant_id 'test-tenant', got %q", cfg.Defaults.TenantID)
	}
	if cfg.Defaults.Compliance != "zt" {
		t.Errorf("expected compliance 'zt', got %q", cfg.Defaults.Compliance)
	}
	if !cfg.Defaults.Drift {
		t.Error("expected drift true")
	}
	if !cfg.CIGates.Enabled {
		t.Error("expected ci_gates.enabled true")
	}
	if cfg.CIGates.CriticalThreshold != 3 {
		t.Errorf("expected critical_threshold 3, got %d", cfg.CIGates.CriticalThreshold)
	}
	if cfg.APIServer.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.APIServer.Port)
	}
}

func TestLoadConfig_EnvExpansion(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "argus.yaml")

	t.Setenv("ARGUS_TEST_TENANT", "expanded-tenant-id")
	t.Setenv("ARGUS_TEST_KEY", "secret-key-123")

	content := `
defaults:
  tenant_id: "${ARGUS_TEST_TENANT}"
api_server:
  auth_key: "${ARGUS_TEST_KEY}"
  port: 8443
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Defaults.TenantID != "expanded-tenant-id" {
		t.Errorf("expected expanded tenant_id, got %q", cfg.Defaults.TenantID)
	}
	if cfg.APIServer.AuthKey != "secret-key-123" {
		t.Errorf("expected expanded auth_key, got %q", cfg.APIServer.AuthKey)
	}
}

func TestLoadConfig_EnvExpansion_Unresolved(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "argus.yaml")

	// Make sure this var is not set.
	os.Unsetenv("ARGUS_NONEXISTENT_VAR")

	content := `
defaults:
  tenant_id: "${ARGUS_NONEXISTENT_VAR}"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unresolved vars are left as-is.
	if cfg.Defaults.TenantID != "${ARGUS_NONEXISTENT_VAR}" {
		t.Errorf("expected unresolved var preserved, got %q", cfg.Defaults.TenantID)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "argus.yaml")

	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_FirstPathWins(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	second := filepath.Join(dir, "second.yaml")

	os.WriteFile(first, []byte("defaults:\n  compliance: cis\n"), 0644)
	os.WriteFile(second, []byte("defaults:\n  compliance: zt\n"), 0644)

	cfg, err := LoadConfig(first, second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Defaults.Compliance != "cis" {
		t.Errorf("expected first file to win with 'cis', got %q", cfg.Defaults.Compliance)
	}
}

func TestLoadConfig_SkipsMissing_UsesSecond(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	present := filepath.Join(dir, "present.yaml")

	os.WriteFile(present, []byte("defaults:\n  compliance: zt\n"), 0644)

	cfg, err := LoadConfig(missing, present)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Defaults.Compliance != "zt" {
		t.Errorf("expected 'zt' from second path, got %q", cfg.Defaults.Compliance)
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

func TestValidate_WebhookMissingURL(t *testing.T) {
	cfg := &Config{
		Webhooks: []WebhookConfig{
			{Name: "test", URL: ""},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for missing webhook URL")
	}
}

func TestValidate_WebhookInvalidURL(t *testing.T) {
	cfg := &Config{
		Webhooks: []WebhookConfig{
			{Name: "test", URL: "not-a-url"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid webhook URL")
	}
}

func TestValidate_WebhookValidURL(t *testing.T) {
	cfg := &Config{
		Webhooks: []WebhookConfig{
			{
				Name:   "slack",
				URL:    "https://hooks.slack.com/test",
				Format: "slack",
				Events: []string{"on-complete", "on-critical"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid webhook should pass: %v", err)
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := &Config{
		APIServer: APIServerConfig{Port: 99999},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid port")
	}
}

func TestValidate_TLSMismatch(t *testing.T) {
	cfg := &Config{
		APIServer: APIServerConfig{
			Port:    8443,
			TLSCert: "/path/to/cert.pem",
			// TLSKey intentionally missing
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for TLS cert/key mismatch")
	}
}

func TestValidate_InvalidCompliance(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{Compliance: "nist"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for unknown compliance framework")
	}
}

func TestValidate_InvalidOutput(t *testing.T) {
	cfg := &Config{
		Defaults: DefaultsConfig{Output: "pdf"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for unknown output format")
	}
}

func TestValidate_WebhookBadFormat(t *testing.T) {
	cfg := &Config{
		Webhooks: []WebhookConfig{
			{Name: "test", URL: "https://example.com", Format: "xml"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for unsupported webhook format")
	}
}

func TestValidate_WebhookBadEvent(t *testing.T) {
	cfg := &Config{
		Webhooks: []WebhookConfig{
			{Name: "test", URL: "https://example.com", Events: []string{"on-unknown"}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for unknown webhook event")
	}
}

func TestValidate_CIGatesExitCode(t *testing.T) {
	cfg := &Config{
		CIGates: CIGatesConfig{ExitCodeOnFail: 300},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for exit code > 255")
	}
}

func TestValidate_NegativeMinScore(t *testing.T) {
	cfg := &Config{
		CIGates: CIGatesConfig{MinScore: -1.0},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for negative min_score")
	}
}

func TestLoadConfig_WithWebhooks(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "argus.yaml")

	content := `
webhooks:
  - name: slack-alerts
    url: "https://hooks.slack.com/services/T00/B00/xxx"
    format: slack
    events:
      - on-critical
      - on-chain
    timeout: 30
    headers:
      X-Custom: "value"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(cfg.Webhooks))
	}
	wh := cfg.Webhooks[0]
	if wh.Name != "slack-alerts" {
		t.Errorf("expected name 'slack-alerts', got %q", wh.Name)
	}
	if wh.Format != "slack" {
		t.Errorf("expected format 'slack', got %q", wh.Format)
	}
	if len(wh.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(wh.Events))
	}
	if wh.Headers["X-Custom"] != "value" {
		t.Errorf("expected header X-Custom='value', got %q", wh.Headers["X-Custom"])
	}
}

func TestExpandEnvVars(t *testing.T) {
	t.Setenv("FOO", "bar")

	tests := []struct {
		input    string
		expected string
	}{
		{"${FOO}", "bar"},
		{"prefix-${FOO}-suffix", "prefix-bar-suffix"},
		{"no-vars-here", "no-vars-here"},
		{"${UNSET_VAR_12345}", "${UNSET_VAR_12345}"},
		{"${FOO}/${FOO}", "bar/bar"},
	}

	for _, tt := range tests {
		got := expandEnvVars(tt.input)
		if got != tt.expected {
			t.Errorf("expandEnvVars(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
