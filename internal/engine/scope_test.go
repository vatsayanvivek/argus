package engine

import (
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

func TestClassifyScope(t *testing.T) {
	cases := []struct {
		name, id, rtype string
		want            string
	}{
		{"empty", "", "", models.ScopeTenant},
		{"literal tenant", "tenant", "", models.ScopeTenant},
		{"directory root", "/", "", models.ScopeTenant},
		{"subscription only", "/subscriptions/00000000-0000-0000-0000-000000000000", "", models.ScopeSubscription},
		{"rg level", "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1", "", models.ScopeResourceGroup},
		{"full arm path", "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1", "Microsoft.Storage/storageAccounts", models.ScopeResource},
		{"defender plan", "VirtualMachines", "", models.ScopeSubscription},
		{"terraform-plan sentinel", "terraform-plan", "", models.ScopeSubscription},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyScope(c.id, c.rtype)
			if got != c.want {
				t.Errorf("classifyScope(%q, %q) = %q, want %q", c.id, c.rtype, got, c.want)
			}
		})
	}
}

func TestCollapseDuplicates_CollapsesSubscriptionScope(t *testing.T) {
	// Three instances of the same subscription-scope rule with identical
	// title — must collapse to one with AffectedResources carrying the
	// other two IDs.
	in := []models.Finding{
		{ID: "cis_2_1", Title: "Defender for Servers disabled", Scope: models.ScopeSubscription, ResourceID: "VirtualMachines"},
		{ID: "cis_2_1", Title: "Defender for Servers disabled", Scope: models.ScopeSubscription, ResourceID: "AppServices"},
		{ID: "cis_2_1", Title: "Defender for Servers disabled", Scope: models.ScopeSubscription, ResourceID: "SqlServers"},
	}
	out := CollapseDuplicates(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 collapsed finding, got %d", len(out))
	}
	if len(out[0].AffectedResources) != 2 {
		t.Errorf("expected 2 affected resources, got %d", len(out[0].AffectedResources))
	}
}

func TestCollapseDuplicates_KeepsDistinctResourceFindings(t *testing.T) {
	// Two resource-scope findings with different detail strings must
	// NOT collapse — they describe distinct misconfigurations.
	in := []models.Finding{
		{ID: "zt_net_001", Title: "NSG allows SSH from Internet", Scope: models.ScopeResource, ResourceID: "nsg-a", Detail: "nsg-a AllowSSH rule 100"},
		{ID: "zt_net_001", Title: "NSG allows SSH from Internet", Scope: models.ScopeResource, ResourceID: "nsg-b", Detail: "nsg-b AllowSSH rule 110"},
	}
	out := CollapseDuplicates(in)
	if len(out) != 2 {
		t.Fatalf("distinct resource findings must not collapse, got %d", len(out))
	}
}

func TestCollapseDuplicates_CollapsesIdenticalResourceFindings(t *testing.T) {
	// If detail is identical, the findings ARE logically the same
	// (e.g., "no diagnostic settings" fires on every KV / Storage etc.
	// with the same detail string). Those should collapse.
	in := []models.Finding{
		{ID: "zt_vis_001", Title: "Security-relevant resource has no diagnostic settings", Scope: models.ScopeResource, ResourceID: "kv-a", Detail: "Diagnostic settings absent"},
		{ID: "zt_vis_001", Title: "Security-relevant resource has no diagnostic settings", Scope: models.ScopeResource, ResourceID: "kv-b", Detail: "Diagnostic settings absent"},
		{ID: "zt_vis_001", Title: "Security-relevant resource has no diagnostic settings", Scope: models.ScopeResource, ResourceID: "kv-c", Detail: "Diagnostic settings absent"},
	}
	out := CollapseDuplicates(in)
	if len(out) != 1 {
		t.Fatalf("identical detail findings should collapse, got %d", len(out))
	}
	if len(out[0].AffectedResources) != 2 {
		t.Errorf("expected 2 affected resources in collapsed entry, got %d", len(out[0].AffectedResources))
	}
}
