package drift

import (
	"testing"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

func TestDriftAnalyzer_HighUnusedPercentage(t *testing.T) {
	// Contributor grants a broad set of resource actions. Observing only
	// two of them should result in a large unused percentage.
	snap := &models.AzureSnapshot{
		Identity: models.IdentitySnapshot{
			RoleAssignments: []models.RoleAssignment{
				{
					ID:            "ra1",
					PrincipalID:   "principal-1",
					PrincipalType: "ServicePrincipal",
					RoleName:      "Contributor",
					Scope:         "/subscriptions/test",
				},
			},
			ServicePrincipals: []models.ServicePrincipal{
				{ID: "principal-1", DisplayName: "test-sp"},
			},
		},
		ActivityLog: []models.ActivityEvent{
			{
				Caller:        "principal-1",
				OperationName: "Microsoft.Storage/storageAccounts/read",
				Timestamp:     time.Now(),
			},
			{
				Caller:        "principal-1",
				OperationName: "Microsoft.Compute/virtualMachines/read",
				Timestamp:     time.Now(),
			},
		},
	}

	analyzer := NewAnalyzer(snap.ActivityLog)
	findings := analyzer.Analyze(snap, 30)

	if len(findings) == 0 {
		t.Fatal("expected at least one drift finding")
	}
	found := false
	for _, df := range findings {
		if df.IdentityARN == "principal-1" {
			found = true
			if df.UnusedPercentage < 50.0 {
				t.Errorf("expected high unused %% for Contributor with 2 used actions, got %.1f", df.UnusedPercentage)
			}
			if df.IdentityType != "ServicePrincipal" {
				t.Errorf("expected ServicePrincipal type, got %s", df.IdentityType)
			}
		}
	}
	if !found {
		t.Error("drift finding for principal-1 not found")
	}
}

func TestDriftAnalyzer_NoActivityMeansMaxUnused(t *testing.T) {
	snap := &models.AzureSnapshot{
		Identity: models.IdentitySnapshot{
			RoleAssignments: []models.RoleAssignment{
				{
					ID:            "ra1",
					PrincipalID:   "dormant-principal",
					PrincipalType: "User",
					RoleName:      "Owner",
					Scope:         "/subscriptions/test",
				},
			},
			Users: []models.AADUser{
				{ID: "dormant-principal", DisplayName: "dormant-user"},
			},
		},
		ActivityLog: []models.ActivityEvent{},
	}
	analyzer := NewAnalyzer(snap.ActivityLog)
	findings := analyzer.Analyze(snap, 0)
	if len(findings) == 0 {
		t.Fatal("expected a finding for the dormant principal")
	}
	df := findings[0]
	if df.UnusedPercentage != 100.0 {
		t.Errorf("expected 100%% unused for dormant Owner, got %.1f", df.UnusedPercentage)
	}
	if df.BlastRadius != "CRITICAL" {
		t.Errorf("expected CRITICAL blast radius, got %s", df.BlastRadius)
	}
	if df.IdentityName != "dormant-user" {
		t.Errorf("expected identity name dormant-user, got %s", df.IdentityName)
	}
}

func TestDriftAnalyzer_OlderThanWindowExcluded(t *testing.T) {
	// Place the activity far in the past so the 1-day window drops it.
	oldTime := time.Now().Add(-90 * 24 * time.Hour)
	snap := &models.AzureSnapshot{
		Identity: models.IdentitySnapshot{
			RoleAssignments: []models.RoleAssignment{
				{
					ID:            "ra1",
					PrincipalID:   "principal-old",
					PrincipalType: "ServicePrincipal",
					RoleName:      "Contributor",
					Scope:         "/subscriptions/test",
				},
			},
			ServicePrincipals: []models.ServicePrincipal{
				{ID: "principal-old", DisplayName: "old-sp"},
			},
		},
		ActivityLog: []models.ActivityEvent{
			{Caller: "principal-old", OperationName: "Microsoft.Storage/storageAccounts/read", Timestamp: oldTime},
		},
	}

	analyzer := NewAnalyzer(snap.ActivityLog)
	findings := analyzer.Analyze(snap, 1)

	if len(findings) == 0 {
		t.Fatal("expected a drift finding")
	}
	// Since the only log entry is older than the 1-day window, the
	// principal should appear to have no observed activity.
	if findings[0].UnusedPercentage < 99.0 {
		t.Errorf("expected near 100%% unused after filtering old events, got %.1f", findings[0].UnusedPercentage)
	}
}

func TestDriftAnalyzer_BlastRadiusBuckets(t *testing.T) {
	cases := []struct {
		pct  float64
		want string
	}{
		{100, "CRITICAL"},
		{85, "CRITICAL"},
		{70, "HIGH"},
		{50, "MEDIUM"},
		{20, "LOW"},
		{0, "LOW"},
	}
	for _, c := range cases {
		got := blastRadiusFor(c.pct)
		if got != c.want {
			t.Errorf("blastRadiusFor(%.0f)=%s, want %s", c.pct, got, c.want)
		}
	}
}

func TestDriftAnalyzer_NilSnapshot(t *testing.T) {
	analyzer := NewAnalyzer(nil)
	findings := analyzer.Analyze(nil, 30)
	if findings != nil && len(findings) > 0 {
		t.Error("nil snapshot should produce no findings")
	}
}
