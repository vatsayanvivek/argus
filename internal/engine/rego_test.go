package engine

import (
	"testing"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

func newTestSnapshot() *models.AzureSnapshot {
	return &models.AzureSnapshot{
		SubscriptionID:     "00000000-0000-0000-0000-000000000001",
		SubscriptionName:   "test-sub",
		TenantID:           "00000000-0000-0000-0000-0000000000ff",
		ScanTime:           time.Now(),
		DefenderPlans:      map[string]string{},
		DiagnosticSettings: map[string]bool{},
	}
}

// nsgWithInboundRule constructs an NSG resource with one inbound rule.
func nsgWithInboundRule(id, name, port, src string) models.AzureResource {
	return models.AzureResource{
		ID:   id,
		Name: name,
		Type: "microsoft.network/networksecuritygroups",
		Properties: map[string]interface{}{
			"securityRules": []interface{}{
				map[string]interface{}{
					"name": "AllowMgmt",
					"properties": map[string]interface{}{
						"direction":            "Inbound",
						"access":               "Allow",
						"protocol":             "Tcp",
						"destinationPortRange": port,
						"sourceAddressPrefix":  src,
					},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// zt_net_001 — SSH open to the internet.
// ---------------------------------------------------------------------------

func TestRegoZTNet001_SSHOpenToInternet(t *testing.T) {
	snap := newTestSnapshot()
	snap.Resources = []models.AzureResource{
		nsgWithInboundRule("/sub/test/nsg/web-nsg", "web-nsg", "22", "*"),
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := engine.Evaluate(snap, "all")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.ID == "zt_net_001" {
			found = true
			if f.ResourceName != "web-nsg" {
				t.Errorf("expected resource_name web-nsg, got %s", f.ResourceName)
			}
			if f.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL, got %s", f.Severity)
			}
			if f.Pillar != "Network" {
				t.Errorf("expected Network pillar, got %s", f.Pillar)
			}
		}
	}
	if !found {
		t.Error("zt_net_001 should have detected SSH from internet")
	}
}

func TestRegoZTNet001_RestrictedCIDR_NoViolation(t *testing.T) {
	snap := newTestSnapshot()
	snap.Resources = []models.AzureResource{
		nsgWithInboundRule("/sub/test/nsg/web-nsg", "web-nsg", "22", "10.0.0.0/8"),
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := engine.Evaluate(snap, "all")

	for _, f := range findings {
		if f.ID == "zt_net_001" {
			t.Errorf("zt_net_001 should NOT fire when CIDR is restricted (got %+v)", f)
		}
	}
}

// ---------------------------------------------------------------------------
// zt_id_011 — App Registration with high-privilege Graph permission.
// ---------------------------------------------------------------------------

func TestRegoZTID011_HighPrivilegeGraphPerm(t *testing.T) {
	snap := newTestSnapshot()
	// Application.ReadWrite.All application-level permission on Graph.
	snap.Identity.AppRegistrations = []models.AppRegistration{
		{
			ID:          "/sub/test/app/example-app",
			DisplayName: "example-app",
			AppID:       "12345678-1234-1234-1234-123456789012",
			RequiredResourceAccess: []models.ResourceAccess{
				{
					ResourceAppID: "00000003-0000-0000-c000-000000000000", // Microsoft Graph
					Permissions: []models.Permission{
						{
							ID:   "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", // Application.ReadWrite.All
							Type: "Role",
						},
					},
				},
			},
		},
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := engine.Evaluate(snap, "all")
	if err != nil {
		t.Fatal(err)
	}

	var hit *models.Finding
	for i := range findings {
		if findings[i].ID == "zt_id_011" {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatal("zt_id_011 should have fired for an App Registration holding Application.ReadWrite.All")
	}
	if hit.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity for zt_id_011, got %s", hit.Severity)
	}
	if hit.Pillar != "Identity" {
		t.Errorf("expected Identity pillar, got %s", hit.Pillar)
	}
}

func TestRegoZTID011_DelegatedPermOnly_NoViolation(t *testing.T) {
	snap := newTestSnapshot()
	// Same permission but Type=Scope (delegated, not dangerous).
	snap.Identity.AppRegistrations = []models.AppRegistration{
		{
			ID:          "/sub/test/app/benign",
			DisplayName: "benign-app",
			AppID:       "12345678-1234-1234-1234-123456789012",
			RequiredResourceAccess: []models.ResourceAccess{
				{
					ResourceAppID: "00000003-0000-0000-c000-000000000000",
					Permissions: []models.Permission{
						{
							ID:   "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",
							Type: "Scope", // delegated -> not dangerous
						},
					},
				},
			},
		},
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := engine.Evaluate(snap, "all")

	for _, f := range findings {
		if f.ID == "zt_id_011" {
			t.Errorf("zt_id_011 should NOT fire for delegated (Scope) permission, got %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// zt_data_001 — Storage account with public blob access.
// ---------------------------------------------------------------------------

func TestRegoZTData001_PublicBlobAccess(t *testing.T) {
	snap := newTestSnapshot()
	snap.Resources = []models.AzureResource{
		{
			ID:   "/sub/test/sa/publicdata",
			Name: "publicdata",
			Type: "microsoft.storage/storageaccounts",
			Properties: map[string]interface{}{
				"allowBlobPublicAccess": true,
			},
		},
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := engine.Evaluate(snap, "all")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.ID == "zt_data_001" {
			found = true
			if f.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL severity, got %s", f.Severity)
			}
			if f.Pillar != "Data" {
				t.Errorf("expected Data pillar, got %s", f.Pillar)
			}
		}
	}
	if !found {
		t.Error("zt_data_001 should have fired for allowBlobPublicAccess=true")
	}
}

// ---------------------------------------------------------------------------
// zt_vis_003 — Defender plans on Free tier.
// ---------------------------------------------------------------------------

func TestRegoZTVis003_DefenderFreeTier(t *testing.T) {
	snap := newTestSnapshot()
	snap.DefenderPlans = map[string]string{
		"VirtualMachines":  "Free",
		"StorageAccounts":  "Standard",
		"KeyVaults":        "Standard",
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := engine.Evaluate(snap, "all")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.ID == "zt_vis_003" {
			found = true
		}
	}
	if !found {
		t.Error("zt_vis_003 should have fired for at least one Free-tier defender plan")
	}
}

func TestRegoZTVis003_DefenderStandard_NoViolation(t *testing.T) {
	snap := newTestSnapshot()
	snap.DefenderPlans = map[string]string{
		"VirtualMachines": "Standard",
		"StorageAccounts": "Standard",
		"KeyVaults":       "Standard",
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := engine.Evaluate(snap, "all")

	for _, f := range findings {
		if f.ID == "zt_vis_003" {
			t.Errorf("zt_vis_003 should NOT fire when every plan is Standard (got %+v)", f)
		}
	}
}

// ---------------------------------------------------------------------------
// cis_6_1 — SSH exposed to internet (CIS rule variant).
// ---------------------------------------------------------------------------

func TestRegoCIS61_SSHFromInternet(t *testing.T) {
	snap := newTestSnapshot()
	snap.Resources = []models.AzureResource{
		nsgWithInboundRule("/sub/test/nsg/web-nsg", "web-nsg", "22", "0.0.0.0/0"),
	}

	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := engine.Evaluate(snap, "all")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.ID == "cis_6_1" {
			found = true
			if f.Pillar != "Network" {
				t.Errorf("expected Network pillar, got %s", f.Pillar)
			}
		}
	}
	if !found {
		t.Error("cis_6_1 should have fired for SSH exposed to 0.0.0.0/0")
	}
}

// ---------------------------------------------------------------------------
// Engine bootstrap sanity test.
// ---------------------------------------------------------------------------

func TestOPAEngine_LoadsPolicies(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatal(err)
	}
	meta := engine.PolicyMetadata()
	if len(meta) == 0 {
		t.Fatal("expected at least one policy loaded from embedded FS")
	}
	// Known policies that must be present for the other rego tests.
	// Must load all 201 policies.
	if len(meta) < 201 {
		t.Errorf("expected at least 201 policies loaded, got %d", len(meta))
	}
	for _, id := range []string{"zt_net_001", "zt_data_001", "zt_vis_003", "cis_6_1", "zt_id_012", "zt_net_011", "zt_data_011", "zt_wl_014", "zt_vis_011", "zt_id_026"} {
		if _, ok := meta[id]; !ok {
			t.Errorf("expected policy %s to be loaded", id)
		}
	}
}
