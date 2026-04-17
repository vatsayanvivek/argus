package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

func TestHTMLReporter_GeneratesValidReport(t *testing.T) {
	reporter := NewHTMLReporter()
	if reporter.tmpl == nil {
		t.Fatal("HTML template failed to load from embedded FS")
	}

	snap := &models.AzureSnapshot{
		SubscriptionID:   "00000000-0000-0000-0000-000000000001",
		SubscriptionName: "test-sub",
		TenantID:         "00000000-0000-0000-0000-0000000000ff",
		ScanTime:         time.Now(),
		CollectionMode:   "full",
	}
	score := &models.ZTScoreReport{
		OverallScore:  85.0,
		Grade:         "B",
		MaturityLevel: "Advanced",
		PillarScores: map[string]models.PillarScore{
			"Identity": {Score: 90, Grade: "A", TenetStatus: "SATISFIED"},
			"Network":  {Score: 80, Grade: "B", TenetStatus: "SATISFIED"},
		},
		FindingsBySeverity: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		ChainsBySeverity:   map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
	}

	tmpDir := t.TempDir()
	out := filepath.Join(tmpDir, "report.html")
	err := reporter.Generate(snap, []models.Finding{}, []models.AttackChain{}, score, nil, out)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < 5000 {
		t.Errorf("report too small: %d bytes", info.Size())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "ARGUS") {
		t.Error("report should contain ARGUS branding")
	}
	// No external CDN references - report must be fully self-contained.
	if strings.Contains(strings.ToLower(content), "cdn.") {
		t.Error("report should not contain CDN references")
	}
}

func TestHTMLReporter_RendersFindingsAndChains(t *testing.T) {
	reporter := NewHTMLReporter()
	if reporter.tmpl == nil {
		t.Fatal("HTML template failed to load")
	}

	snap := &models.AzureSnapshot{
		SubscriptionID:   "test-sub",
		SubscriptionName: "prod-subscription",
		TenantID:         "test-tenant",
		ScanTime:         time.Now(),
	}
	findings := []models.Finding{
		{
			ID:           "zt_net_001",
			Severity:     "CRITICAL",
			Pillar:       "Network",
			Title:        "NSG allows SSH from internet",
			ResourceName: "web-nsg",
			ResourceID:   "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg",
			Description:  "SSH is exposed to 0.0.0.0/0",
		},
	}
	chains := []models.AttackChain{
		{
			ID:              "CHAIN-001",
			Title:           "Internet-exposed VM to subscription takeover",
			Severity:        "CRITICAL",
			Likelihood:      "High",
			Narrative:       "Attack narrative text",
			TriggerFindings: []string{"zt_net_001"},
			Steps: []models.ChainStep{
				{Number: 1, Actor: "Attacker", Action: "Scan IPs", Technique: "T1595.001"},
			},
			MinimalFixSet: []string{"zt_net_001"},
		},
	}
	score := &models.ZTScoreReport{
		OverallScore:       60.0,
		Grade:              "C",
		MaturityLevel:      "Defined",
		PillarScores:       map[string]models.PillarScore{"Network": {Score: 60, Grade: "C"}},
		FindingsBySeverity: map[string]int{"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		ChainsBySeverity:   map[string]int{"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		TotalFindings:      1,
		ChainsDetected:     1,
	}

	out := filepath.Join(t.TempDir(), "report.html")
	if err := reporter.Generate(snap, findings, chains, score, nil, out); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "CHAIN-001") {
		t.Error("expected rendered report to contain CHAIN-001 id")
	}
	if !strings.Contains(content, "web-nsg") {
		t.Error("expected rendered report to contain the finding's resource name")
	}
}
