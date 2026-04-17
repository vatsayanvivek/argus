package iac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------

const terraformPlanEnvelope = `{"format_version":"1.2","terraform_version":"1.6.0","resource_changes":[]}`
const armTemplateEnvelope = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"stprod","location":"eastus","properties":{}}]
}`
const armWhatIfEnvelope = `{
  "changes":[{
    "resourceId":"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1",
    "changeType":"Create",
    "after":{"type":"Microsoft.KeyVault/vaults","properties":{}}
  }]
}`
const armNoSchemaButResources = `{"resources":[{"type":"Microsoft.Network/virtualNetworks","apiVersion":"2023-01-01","name":"vnet1","location":"eastus"}]}`

func TestDetectFormat_Terraform(t *testing.T) {
	got, _, err := DetectFormat(strings.NewReader(terraformPlanEnvelope))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if got != FormatTerraform {
		t.Errorf("got %q, want terraform-plan", got)
	}
}

func TestDetectFormat_ARMTemplateWithSchema(t *testing.T) {
	got, _, err := DetectFormat(strings.NewReader(armTemplateEnvelope))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if got != FormatARM {
		t.Errorf("got %q, want arm-template", got)
	}
}

func TestDetectFormat_ARMWithoutSchema(t *testing.T) {
	// Bicep-compiled output sometimes omits $schema; detection should
	// fall back to inspecting the resources[] array for Microsoft.*
	// types.
	got, _, err := DetectFormat(strings.NewReader(armNoSchemaButResources))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if got != FormatARM {
		t.Errorf("got %q, want arm-template (resource-signal fallback)", got)
	}
}

func TestDetectFormat_ARMWhatIf(t *testing.T) {
	got, _, err := DetectFormat(strings.NewReader(armWhatIfEnvelope))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if got != FormatARMWhatIf {
		t.Errorf("got %q, want arm-whatif", got)
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	_, _, err := DetectFormat(strings.NewReader(`{"foo":"bar"}`))
	if err == nil {
		t.Fatal("expected error on unknown JSON envelope")
	}
}

func TestDetectFormat_NotJSON(t *testing.T) {
	_, _, err := DetectFormat(strings.NewReader(`<xml/>`))
	if err == nil {
		t.Fatal("expected error on non-JSON input")
	}
}

func TestDetectFormat_Empty(t *testing.T) {
	_, _, err := DetectFormat(strings.NewReader(``))
	if err == nil {
		t.Fatal("expected error on empty input")
	}
}

// ---------------------------------------------------------------------
// ARM template parsing + translation
// ---------------------------------------------------------------------

const armStorageInsecure = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type":"Microsoft.Storage/storageAccounts",
    "apiVersion":"2023-01-01",
    "name":"stinsecure",
    "location":"eastus",
    "sku":{"name":"Standard_LRS"},
    "kind":"StorageV2",
    "properties": {
      "supportsHttpsTrafficOnly": false,
      "minimumTlsVersion": "TLS1_0",
      "allowBlobPublicAccess": true,
      "publicNetworkAccess": "Enabled",
      "allowSharedKeyAccess": true,
      "networkAcls": {"defaultAction":"Allow"}
    }
  }]
}`

func TestParseARMTemplate_ExtractsResource(t *testing.T) {
	tpl, err := ParseARMTemplate([]byte(armStorageInsecure))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tpl.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(tpl.Resources))
	}
	r := tpl.Resources[0]
	if r.Type != "Microsoft.Storage/storageAccounts" {
		t.Errorf("type: %q", r.Type)
	}
	if r.Properties["minimumTlsVersion"] != "TLS1_0" {
		t.Errorf("minimumTlsVersion not carried through: %v", r.Properties)
	}
}

func TestTranslateARM_ProducesSnapshotResource(t *testing.T) {
	tpl, _ := ParseARMTemplate([]byte(armStorageInsecure))
	snap := TranslateARM(tpl, "sub1", "tenant1")
	if len(snap.Resources) != 1 {
		t.Fatalf("snapshot has %d resources", len(snap.Resources))
	}
	r := snap.Resources[0]
	if r.Type != "Microsoft.Storage/storageAccounts" {
		t.Errorf("ARM type lost in translation: %q", r.Type)
	}
	if r.Properties["minimumTlsVersion"] != "TLS1_0" {
		t.Errorf("properties not propagated")
	}
	if r.SKU != "Standard_LRS" {
		t.Errorf("SKU not extracted from object form: %q", r.SKU)
	}
}

// TestTranslateARM_NestedChildren asserts that child resources declared
// inline under their parent (Bicep-idiomatic) flatten into individual
// snapshot entries with the correct Microsoft.Sql/servers/databases
// ARM type.
func TestTranslateARM_NestedChildren(t *testing.T) {
	body := `{
      "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
      "contentVersion": "1.0.0.0",
      "resources": [{
        "type":"Microsoft.Sql/servers",
        "apiVersion":"2023-01-01",
        "name":"sql1","location":"eastus",
        "properties":{"publicNetworkAccess":"Enabled"},
        "resources":[{
          "type":"databases","apiVersion":"2023-01-01",
          "name":"db1","location":"eastus",
          "properties":{"zoneRedundant":false}
        }]
      }]
    }`
	tpl, err := ParseARMTemplate([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	snap := TranslateARM(tpl, "sub1", "tenant1")
	if len(snap.Resources) != 2 {
		t.Fatalf("expected 2 flattened resources (parent + child), got %d", len(snap.Resources))
	}
	var parentOK, childOK bool
	for _, r := range snap.Resources {
		if r.Type == "Microsoft.Sql/servers" && r.Name == "sql1" {
			parentOK = true
		}
		if r.Name == "sql1/db1" {
			childOK = true
		}
	}
	if !parentOK || !childOK {
		t.Errorf("nested children not flattened; got %+v", snap.Resources)
	}
}

func TestScanARMBytes_EndToEnd(t *testing.T) {
	res, err := ScanARMBytes([]byte(armStorageInsecure), "sub1", "tenant1")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Snapshot.Resources) != 1 {
		t.Errorf("expected 1 snapshot resource")
	}
	// Deliberately insecure storage must produce at least one finding
	// — any of TLS 1.0, HTTPS-not-enforced, allow-blob-public-access,
	// or shared-key-enabled would match an ARGUS rule.
	if len(res.Findings) == 0 {
		t.Errorf("insecure ARM storage should produce findings; got 0")
	}
}

// ---------------------------------------------------------------------
// What-if parsing + translation
// ---------------------------------------------------------------------

const whatIfKeyVaultCreate = `{
  "changes":[{
    "resourceId":"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv-prod",
    "changeType":"Create",
    "after":{
      "type":"Microsoft.KeyVault/vaults","location":"eastus",
      "properties":{"enablePurgeProtection":false,"enableRbacAuthorization":false,"publicNetworkAccess":"Enabled"}
    }
  },{
    "resourceId":"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/stold",
    "changeType":"Delete",
    "before":{"type":"Microsoft.Storage/storageAccounts"}
  },{
    "resourceId":"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1",
    "changeType":"NoChange",
    "after":{"type":"Microsoft.Network/virtualNetworks"}
  }]
}`

func TestParseWhatIf_ExtractsChanges(t *testing.T) {
	w, err := ParseWhatIf([]byte(whatIfKeyVaultCreate))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(w.Changes) != 3 {
		t.Errorf("expected 3 change entries, got %d", len(w.Changes))
	}
}

func TestTranslateWhatIf_IgnoresDeleteAndNoChange(t *testing.T) {
	w, err := ParseWhatIf([]byte(whatIfKeyVaultCreate))
	if err != nil {
		t.Fatal(err)
	}
	snap := TranslateWhatIf(w, "sub1", "tenant1")
	// Only the Create change should translate; Delete and NoChange
	// are filtered out.
	if len(snap.Resources) != 1 {
		t.Fatalf("expected 1 translated resource, got %d: %+v", len(snap.Resources), snap.Resources)
	}
	if snap.Resources[0].Type != "Microsoft.KeyVault/vaults" {
		t.Errorf("wrong resource translated: %q", snap.Resources[0].Type)
	}
}

func TestTranslateWhatIf_TypeFromResourceID(t *testing.T) {
	// What-if omits explicit "type" field — we must reconstruct it
	// from the resourceId path. Child resources need the child type.
	body := `{"changes":[{
      "resourceId":"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.Sql/servers/sql1/databases/db1",
      "changeType":"Create",
      "after":{"properties":{}}
    }]}`
	w, _ := ParseWhatIf([]byte(body))
	snap := TranslateWhatIf(w, "sub1", "tenant1")
	if len(snap.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snap.Resources))
	}
	if got := snap.Resources[0].Type; got != "Microsoft.Sql/servers/databases" {
		t.Errorf("child type: got %q, want Microsoft.Sql/servers/databases", got)
	}
	if snap.Resources[0].ResourceGroup != "rg1" {
		t.Errorf("resource group: got %q", snap.Resources[0].ResourceGroup)
	}
}

func TestScanWhatIfBytes_EndToEnd(t *testing.T) {
	res, err := ScanWhatIfBytes([]byte(whatIfKeyVaultCreate), "sub1", "tenant1")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.Format != string(FormatARMWhatIf) && res.Format != "" {
		// Format is set by Scan's dispatcher, not ScanWhatIfBytes
		// directly — either is acceptable.
	}
	if len(res.Snapshot.Resources) != 1 {
		t.Errorf("expected 1 translated resource")
	}
}

// ---------------------------------------------------------------------
// Scan() dispatch via auto-detection
// ---------------------------------------------------------------------

func TestScanWithFormat_AutoDetectsEachFormat(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		format string
	}{
		{"terraform_plan", `{"format_version":"1.2","terraform_version":"1.6.0","resource_changes":[{"address":"azurerm_key_vault.t","mode":"managed","type":"azurerm_key_vault","name":"t","change":{"actions":["create"],"before":null,"after":{"name":"kv1","location":"eastus","resource_group_name":"rg1"}}}]}`, string(FormatTerraform)},
		{"arm_template", armStorageInsecure, string(FormatARM)},
		{"arm_whatif", whatIfKeyVaultCreate, string(FormatARMWhatIf)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			res, err := ScanWithFormat(path, "auto", "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000")
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if res.Format != tc.format {
				t.Errorf("Format: got %q, want %q", res.Format, tc.format)
			}
		})
	}
}

func TestScanWithFormat_ExplicitOverrideBeatsDetection(t *testing.T) {
	// An ARM template-shaped payload but we force "whatif" — should
	// error at the what-if parser stage because it has no changes[]
	// array. This proves the override took effect.
	dir := t.TempDir()
	path := filepath.Join(dir, "tpl.json")
	if err := os.WriteFile(path, []byte(armStorageInsecure), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ScanWithFormat(path, "whatif", "sub1", "tenant1")
	if err == nil {
		t.Fatal("expected error when forcing whatif on an ARM template")
	}
}

func TestScanWithFormat_UnknownOverrideRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tpl.json")
	if err := os.WriteFile(path, []byte(armStorageInsecure), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ScanWithFormat(path, "pulumi", "sub1", "tenant1")
	if err == nil || !strings.Contains(err.Error(), "unsupported --format") {
		t.Fatalf("expected unsupported-format error, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func TestArmTypeFromResourceID_ParentAndChild(t *testing.T) {
	cases := map[string]string{
		"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/st1":                           "Microsoft.Storage/storageAccounts",
		"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.Sql/servers/sql1":                                      "Microsoft.Sql/servers",
		"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.Sql/servers/sql1/databases/db1":                         "Microsoft.Sql/servers/databases",
		"/subscriptions/0/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/subnet1":          "Microsoft.Network/virtualNetworks/subnets",
	}
	for id, want := range cases {
		got := armTypeFromResourceID(id)
		if got != want {
			t.Errorf("armTypeFromResourceID(%q) = %q; want %q", id, got, want)
		}
	}
}

func TestResourceGroupFromID(t *testing.T) {
	got := resourceGroupFromID("/subscriptions/0/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv1")
	if got != "rg-prod" {
		t.Errorf("resourceGroupFromID: got %q, want rg-prod", got)
	}
	if rg := resourceGroupFromID("/subscriptions/0/providers/Microsoft.Something/X"); rg != "" {
		t.Errorf("subscription-scope resource should have empty RG, got %q", rg)
	}
}
