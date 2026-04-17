// Package config provides ARGUS configuration file loading and validation.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level ARGUS configuration.
type Config struct {
	Defaults  DefaultsConfig  `yaml:"defaults"`
	CIGates   CIGatesConfig   `yaml:"ci_gates"`
	Webhooks  []WebhookConfig `yaml:"webhooks"`
	APIServer APIServerConfig `yaml:"api_server"`
}

// DefaultsConfig holds default scan parameters.
type DefaultsConfig struct {
	TenantID       string `yaml:"tenant_id"`
	SubscriptionID string `yaml:"subscription_id"`
	Compliance     string `yaml:"compliance"`
	Output         string `yaml:"output"`
	OutputDir      string `yaml:"output_dir"`
	Drift          bool   `yaml:"drift"`
	Evidence       bool   `yaml:"evidence"`
	SuppressFile   string `yaml:"suppress_file"`
}

// CIGatesConfig controls CI/CD pipeline gate behavior.
type CIGatesConfig struct {
	Enabled            bool    `yaml:"enabled"`
	FailOnCritical     bool    `yaml:"fail_on_critical"`
	CriticalThreshold  int     `yaml:"critical_threshold"`
	HighChainThreshold int     `yaml:"high_chain_threshold"`
	MinScore           float64 `yaml:"min_score"`
	ExitCodeOnFail     int     `yaml:"exit_code_on_fail"`
}

// WebhookConfig defines a notification webhook endpoint.
type WebhookConfig struct {
	Name    string            `yaml:"name"`
	URL     string            `yaml:"url"`
	Format  string            `yaml:"format"` // json, slack, teams
	Events  []string          `yaml:"events"` // on-complete, on-critical, on-chain
	Timeout int               `yaml:"timeout"`
	Headers map[string]string `yaml:"headers"`
}

// APIServerConfig holds API server settings.
type APIServerConfig struct {
	Port    int    `yaml:"port"`
	Workers int    `yaml:"workers"`
	AuthKey string `yaml:"auth_key"`
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Defaults: DefaultsConfig{
			Compliance:   "cis",
			Output:       "json",
			OutputDir:    "./argus-output",
			Drift:        false,
			Evidence:     false,
			SuppressFile: "suppress.yaml",
		},
		CIGates: CIGatesConfig{
			Enabled:            false,
			FailOnCritical:     true,
			CriticalThreshold:  1,
			HighChainThreshold: 5,
			MinScore:           0.0,
			ExitCodeOnFail:     2,
		},
		APIServer: APIServerConfig{
			Port:    8443,
			Workers: 4,
		},
	}
}

// LoadConfig loads configuration from the first file found among the given
// paths. If no explicit paths are provided, it searches ./argus.yaml and
// ~/.argus/config.yaml in order. If no file is found at all, a zero-value
// Config is returned (not an error).
func LoadConfig(paths ...string) (*Config, error) {
	searchPaths := paths
	if len(searchPaths) == 0 {
		searchPaths = defaultSearchPaths()
	}

	for _, p := range searchPaths {
		expanded := expandHome(p)
		data, err := os.ReadFile(expanded)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("reading config %s: %w", expanded, err)
		}

		data = []byte(expandEnvVars(string(data)))

		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parsing config %s: %w", expanded, err)
		}
		return &cfg, nil
	}

	// No config file found — return zero-value config.
	cfg := Config{}
	return &cfg, nil
}

// Validate checks the config for obvious misconfigurations.
func (c *Config) Validate() error {
	var errs []string

	// Validate webhooks.
	for i, wh := range c.Webhooks {
		label := wh.Name
		if label == "" {
			label = fmt.Sprintf("webhooks[%d]", i)
		}
		if wh.URL == "" {
			errs = append(errs, fmt.Sprintf("%s: url is required", label))
		} else if u, err := url.Parse(wh.URL); err != nil || u.Scheme == "" {
			errs = append(errs, fmt.Sprintf("%s: invalid url %q", label, wh.URL))
		}

		validFormats := map[string]bool{"json": true, "slack": true, "teams": true, "": true}
		if !validFormats[wh.Format] {
			errs = append(errs, fmt.Sprintf("%s: unsupported format %q (use json, slack, or teams)", label, wh.Format))
		}

		validEvents := map[string]bool{"on-complete": true, "on-critical": true, "on-chain": true}
		for _, ev := range wh.Events {
			if !validEvents[ev] {
				errs = append(errs, fmt.Sprintf("%s: unknown event %q", label, ev))
			}
		}

		if wh.Timeout < 0 {
			errs = append(errs, fmt.Sprintf("%s: timeout must be non-negative", label))
		}
	}

	// Validate API server port.
	if c.APIServer.Port != 0 && (c.APIServer.Port < 1 || c.APIServer.Port > 65535) {
		errs = append(errs, fmt.Sprintf("api_server.port: %d is out of range (1-65535)", c.APIServer.Port))
	}

	// Validate API server workers.
	if c.APIServer.Workers < 0 {
		errs = append(errs, "api_server.workers: must be non-negative")
	}

	// Validate TLS pair: both or neither.
	if (c.APIServer.TLSCert == "") != (c.APIServer.TLSKey == "") {
		errs = append(errs, "api_server: tls_cert and tls_key must both be set or both be empty")
	}

	// CI gates checks.
	if c.CIGates.ExitCodeOnFail < 0 || c.CIGates.ExitCodeOnFail > 255 {
		errs = append(errs, fmt.Sprintf("ci_gates.exit_code_on_fail: %d is out of range (0-255)", c.CIGates.ExitCodeOnFail))
	}
	if c.CIGates.MinScore < 0 {
		errs = append(errs, "ci_gates.min_score: must be non-negative")
	}

	// Validate compliance framework value if set.
	validCompliance := map[string]bool{"cis": true, "zt": true, "all": true, "": true}
	if !validCompliance[c.Defaults.Compliance] {
		errs = append(errs, fmt.Sprintf("defaults.compliance: unknown framework %q", c.Defaults.Compliance))
	}

	// Validate output format if set.
	validOutput := map[string]bool{"json": true, "html": true, "sarif": true, "": true}
	if !validOutput[c.Defaults.Output] {
		errs = append(errs, fmt.Sprintf("defaults.output: unknown format %q", c.Defaults.Output))
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// envVarPattern matches ${VAR_NAME} placeholders.
var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// expandEnvVars replaces all ${VAR} references in s with their env var values.
func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[2 : len(match)-1]
		if val, ok := os.LookupEnv(varName); ok {
			return val
		}
		return match // leave unresolved vars as-is
	})
}

// expandHome expands a leading ~ to the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// defaultSearchPaths returns the standard config file search locations.
func defaultSearchPaths() []string {
	return []string{
		"./argus.yaml",
		"~/.argus/config.yaml",
	}
}
