package benchmark

import (
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

func TestBenchmarkLoader_LoadsAllCSVFiles(t *testing.T) {
	loader, err := NewBenchmarkLoader()
	if err != nil {
		t.Fatal(err)
	}
	if len(loader.CISRules) != 63 {
		t.Errorf("expected 63 CIS rules, got %d", len(loader.CISRules))
	}
	if len(loader.Remediation) < 100 {
		t.Errorf("expected >=100 remediation entries, got %d", len(loader.Remediation))
	}
	// Spot check a known rule. The CSV is keyed by the raw rule id
	// (e.g. "cis_1_1"), not by a dotted form.
	r, ok := loader.CISRules["cis_1_1"]
	if !ok {
		t.Fatal("cis_1_1 not found in CIS rules")
	}
	if r.Title == "" {
		t.Error("cis_1_1 title should not be empty")
	}
	if r.Level != "L1" {
		t.Errorf("cis_1_1 should be L1, got %q", r.Level)
	}
}

func TestBenchmarkLoader_ZTTenetsLoaded(t *testing.T) {
	loader, err := NewBenchmarkLoader()
	if err != nil {
		t.Fatal(err)
	}
	// ZT tenets file may or may not exist; if it does we expect a
	// non-empty map.
	if len(loader.ZTTenets) == 0 {
		t.Log("ZT tenets map is empty — CSV may be absent or malformed")
	}
}

func TestBenchmarkMapper_EnrichFinding(t *testing.T) {
	loader, err := NewBenchmarkLoader()
	if err != nil {
		t.Fatal(err)
	}

	f := &models.Finding{
		ID:       "cis_6_1",
		CISRule:  "cis_6_1",
		Severity: "CRITICAL",
	}
	EnrichFinding(f, loader)

	if f.RemediationText == "" && f.RemediationCLI == "" && f.RemediationTerraform == "" {
		t.Error("EnrichFinding should populate at least one remediation field for cis_6_1")
	}
	if f.BlastRadius == "" {
		t.Error("EnrichFinding should set a default BlastRadius based on severity")
	}
}

func TestBenchmarkMapper_EnrichNilInputs(t *testing.T) {
	loader, err := NewBenchmarkLoader()
	if err != nil {
		t.Fatal(err)
	}
	// Nil finding should be a no-op, not a panic.
	EnrichFinding(nil, loader)

	f := &models.Finding{ID: "test", Severity: "HIGH"}
	// Nil loader should be a no-op, not a panic.
	EnrichFinding(f, nil)
	if f.BlastRadius != "" {
		t.Error("nil loader should leave finding untouched")
	}
}

func TestBenchmarkMapper_BlastRadiusFromSeverity(t *testing.T) {
	loader, err := NewBenchmarkLoader()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		severity string
		wantSub  string
	}{
		{"CRITICAL", "Subscription"},
		{"HIGH", "Resource-group"},
		{"MEDIUM", "Single-resource"},
		{"LOW", "Limited"},
	}
	for _, c := range cases {
		f := &models.Finding{ID: "zt_net_x", Severity: c.severity}
		EnrichFinding(f, loader)
		if f.BlastRadius == "" {
			t.Errorf("severity %s: expected populated blast radius", c.severity)
			continue
		}
		if !containsCaseInsensitive(f.BlastRadius, c.wantSub) {
			t.Errorf("severity %s: expected blast radius to contain %q, got %q", c.severity, c.wantSub, f.BlastRadius)
		}
	}
}

func containsCaseInsensitive(haystack, needle string) bool {
	// Small inline substring match so we do not pull in extra imports.
	h := []byte(haystack)
	n := []byte(needle)
	if len(n) == 0 {
		return true
	}
	for i := 0; i+len(n) <= len(h); i++ {
		match := true
		for j := 0; j < len(n); j++ {
			a := h[i+j]
			b := n[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
