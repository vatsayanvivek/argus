package suppression

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".argusignore")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSuppressions_MissingFile(t *testing.T) {
	list, err := LoadSuppressions("/nonexistent/path/.argusignore")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if list == nil {
		t.Fatal("expected non-nil list for missing file")
	}
	if len(list.Suppressions) != 0 {
		t.Errorf("expected empty list, got %d entries", len(list.Suppressions))
	}
}

func TestLoadSuppressions_Valid(t *testing.T) {
	yaml := `suppressions:
  - rule_id: "zt_net_001"
    resource_id: "/sub/test/sg-123"
    reason: "Lab environment"
    approved_by: "secops"
    expires: "2099-12-31"
    created_at: "2026-01-01"
  - rule_id: "zt_vis_010"
    resource_id: "*"
    reason: "JIT not GA"
    approved_by: "ciso"
    expires: ""
    created_at: "2026-01-01"
`
	p := writeTestFile(t, yaml)
	list, err := LoadSuppressions(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Suppressions) != 2 {
		t.Fatalf("expected 2 suppressions, got %d", len(list.Suppressions))
	}
	if list.Suppressions[0].RuleID != "zt_net_001" {
		t.Errorf("rule_id mismatch: %s", list.Suppressions[0].RuleID)
	}
	if list.Suppressions[1].ResourceID != "*" {
		t.Errorf("expected wildcard, got %s", list.Suppressions[1].ResourceID)
	}
}

func TestIsSuppressed_ExactMatch(t *testing.T) {
	list := &SuppressionList{
		Suppressions: []Suppression{
			{RuleID: "zt_net_001", ResourceID: "/sub/test/sg-123", Reason: "x", ApprovedBy: "y"},
		},
	}
	matched, sup := list.IsSuppressed("zt_net_001", "/sub/test/sg-123")
	if !matched {
		t.Fatal("expected match")
	}
	if sup == nil {
		t.Fatal("nil suppression returned despite match")
	}
}

func TestIsSuppressed_WildcardResource(t *testing.T) {
	list := &SuppressionList{
		Suppressions: []Suppression{
			{RuleID: "zt_vis_010", ResourceID: "*"},
		},
	}
	matched, _ := list.IsSuppressed("zt_vis_010", "/anything/at/all")
	if !matched {
		t.Fatal("wildcard should match any resource")
	}
}

func TestIsSuppressed_SuffixWildcard(t *testing.T) {
	list := &SuppressionList{
		Suppressions: []Suppression{
			{RuleID: "cis_3_4", ResourceID: "*-tfstate"},
		},
	}
	matched, _ := list.IsSuppressed("cis_3_4", "/sub/foo/storage/myaccount-tfstate")
	if !matched {
		t.Fatal("suffix wildcard should match")
	}
	matched, _ = list.IsSuppressed("cis_3_4", "/sub/foo/storage/other")
	if matched {
		t.Fatal("suffix wildcard should NOT match")
	}
}

func TestIsSuppressed_Expired(t *testing.T) {
	list := &SuppressionList{
		Suppressions: []Suppression{
			{RuleID: "zt_net_001", ResourceID: "*", Expires: "2000-01-01"},
		},
	}
	matched, _ := list.IsSuppressed("zt_net_001", "anything")
	if matched {
		t.Fatal("expired suppression must not match")
	}
}

func TestIsSuppressed_FutureExpiry(t *testing.T) {
	future := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
	list := &SuppressionList{
		Suppressions: []Suppression{
			{RuleID: "zt_net_001", ResourceID: "*", Expires: future},
		},
	}
	matched, _ := list.IsSuppressed("zt_net_001", "anything")
	if !matched {
		t.Fatal("future-dated suppression should match")
	}
}

func TestFilterFindings(t *testing.T) {
	list := &SuppressionList{
		Suppressions: []Suppression{
			{RuleID: "zt_net_001", ResourceID: "*", Reason: "lab", ApprovedBy: "x"},
		},
	}
	findings := []models.Finding{
		{ID: "zt_net_001", ResourceID: "/sub/sg-1", Detail: "open ssh"},
		{ID: "zt_net_002", ResourceID: "/sub/sg-2", Detail: "open rdp"},
		{ID: "zt_net_001", ResourceID: "/sub/sg-3", Detail: "open ssh"},
	}
	active, suppressed := list.FilterFindings(findings)
	if len(active) != 1 {
		t.Errorf("expected 1 active finding, got %d", len(active))
	}
	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed findings, got %d", len(suppressed))
	}
	if active[0].ID != "zt_net_002" {
		t.Errorf("active finding should be zt_net_002, got %s", active[0].ID)
	}
	for _, s := range suppressed {
		if !contains(s.Detail, "[SUPPRESSED") {
			t.Errorf("suppressed finding missing annotation: %s", s.Detail)
		}
	}
}

func TestAppendAndReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".argusignore")

	entry := Suppression{
		RuleID:     "zt_net_001",
		ResourceID: "/sub/test/sg-1",
		Reason:     "test",
		ApprovedBy: "tester",
		Expires:    "2099-12-31",
	}
	if err := Append(p, entry); err != nil {
		t.Fatal(err)
	}

	list, err := LoadSuppressions(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Suppressions) != 1 {
		t.Fatalf("expected 1 entry after append, got %d", len(list.Suppressions))
	}
	if list.Suppressions[0].RuleID != "zt_net_001" {
		t.Errorf("rule_id mismatch")
	}

	// Append a second entry and verify both survive.
	entry2 := Suppression{RuleID: "zt_vis_010", ResourceID: "*", Reason: "x", ApprovedBy: "y"}
	if err := Append(p, entry2); err != nil {
		t.Fatal(err)
	}
	list, _ = LoadSuppressions(p)
	if len(list.Suppressions) != 2 {
		t.Fatalf("expected 2 entries after second append, got %d", len(list.Suppressions))
	}
}

func TestWarnings_ExpiredAndExpiring(t *testing.T) {
	expiringSoon := time.Now().Add(7 * 24 * time.Hour).Format("2006-01-02")
	list := &SuppressionList{
		Suppressions: []Suppression{
			{RuleID: "zt_net_001", Expires: "2000-01-01"},   // expired
			{RuleID: "zt_net_002", Expires: expiringSoon},    // expiring < 30d
			{RuleID: "", Expires: "2099-01-01"},               // missing rule id
		},
	}
	warnings := list.Warnings()
	if len(warnings) < 3 {
		t.Errorf("expected at least 3 warnings, got %d: %v", len(warnings), warnings)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && stringContains(s, sub)
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
