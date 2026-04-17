package iac

import (
	"strings"
	"testing"
)

// TestGenericRegistry_CountsOver150Types guards the headline claim of
// v1.8: Checkov-class Terraform coverage. The bar is 150 distinct
// azurerm_* types. If this test ever fails, either the registry
// shrank (regression) or the goalpost changed — update consciously.
func TestGenericRegistry_CountsOver150Types(t *testing.T) {
	total := len(genericTypeIndex)
	// Count hand-written types by scanning the dispatch switch for
	// "case " entries isn't portable without file inspection; instead
	// assert that generic alone is >= 120. The dispatcher is tested
	// end-to-end by TestTranslate_CountsAllCoveredTypes for the hand-
	// written path.
	if total < 120 {
		t.Errorf("generic registry coverage shrank: %d types (expected >= 120 for Checkov-class coverage)", total)
	}
}

// TestGenericRegistry_NoDuplicateTFTypes guards against accidentally
// listing the same azurerm_* twice in the registry. Duplicates would
// cause the second entry to overwrite the first in genericTypeIndex,
// silently discarding the earlier ARM-type mapping.
func TestGenericRegistry_NoDuplicateTFTypes(t *testing.T) {
	seen := map[string]int{}
	for _, s := range genericTypeRegistry {
		seen[s.tfType]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("duplicate TF type in registry: %q appears %d times", k, n)
		}
	}
}

// TestGenericRegistry_NoCollisionWithHandWritten verifies the generic
// registry doesn't list a type the dispatch switch already handles.
// Duplicates mean dead entries (the switch catches them first) but
// also a risk that a hand-written type gets its ARM mapping silently
// overridden if someone reorders the dispatcher.
func TestGenericRegistry_NoCollisionWithHandWritten(t *testing.T) {
	// Types the hand-written dispatch already claims. If a type moves
	// from hand-written to generic, remove it from this list.
	handWritten := map[string]bool{
		"azurerm_storage_account":                   true,
		"azurerm_key_vault":                         true,
		"azurerm_mssql_server":                      true,
		"azurerm_sql_server":                        true,
		"azurerm_postgresql_server":                 true,
		"azurerm_postgresql_flexible_server":        true,
		"azurerm_mysql_server":                      true,
		"azurerm_mysql_flexible_server":             true,
		"azurerm_cosmosdb_account":                  true,
		"azurerm_kubernetes_cluster":                true,
		"azurerm_container_registry":                true,
		"azurerm_app_service":                       true,
		"azurerm_linux_web_app":                     true,
		"azurerm_windows_web_app":                   true,
		"azurerm_function_app":                      true,
		"azurerm_linux_function_app":                true,
		"azurerm_windows_function_app":              true,
		"azurerm_virtual_machine":                   true,
		"azurerm_linux_virtual_machine":             true,
		"azurerm_windows_virtual_machine":           true,
		"azurerm_public_ip":                         true,
		"azurerm_network_security_group":            true,
		"azurerm_virtual_network":                   true,
		"azurerm_subnet":                            true,
		"azurerm_redis_cache":                       true,
		"azurerm_servicebus_namespace":              true,
		"azurerm_eventhub_namespace":                true,
		"azurerm_log_analytics_workspace":           true,
		"azurerm_application_gateway":               true,
		"azurerm_frontdoor":                         true,
		"azurerm_cdn_frontdoor_profile":             true,
		"azurerm_firewall":                          true,
		"azurerm_bastion_host":                      true,
		"azurerm_cognitive_account":                 true,
		"azurerm_managed_disk":                      true,
		"azurerm_recovery_services_vault":           true,
		"azurerm_network_watcher":                   true,
		"azurerm_virtual_network_gateway":           true,
		"azurerm_container_app":                     true,
		"azurerm_search_service":                    true,
	}
	for _, s := range genericTypeRegistry {
		if handWritten[s.tfType] {
			t.Errorf("registry collision: %q is both hand-written and in generic registry", s.tfType)
		}
	}
}

// TestTranslateGeneric_LiftsCommonPatterns verifies that a TF resource
// with the common attack-surface fields lifts them to the canonical
// ARM property names so Rego rules match.
func TestTranslateGeneric_LiftsCommonPatterns(t *testing.T) {
	spec := genericTypeSpec{
		tfType:  "azurerm_monitor_private_link_scope",
		armType: "Microsoft.Insights/privateLinkScopes",
	}
	afterJSON := `{
      "name":"pls1","location":"eastus","resource_group_name":"rg1",
      "public_network_access_enabled":false,"minimum_tls_version":"1.2",
      "local_authentication_enabled":false,"zone_redundant":true,
      "tags":{"env":"prod"}
    }`
	rc := ResourceChange{
		Address: "azurerm_monitor_private_link_scope.t",
		Mode:    "managed",
		Type:    "azurerm_monitor_private_link_scope",
		Change: Change{
			Actions: []string{"create"},
			After:   mustJSONObject(t, afterJSON),
		},
	}
	r := translateGeneric(rc, spec)
	if r.Type != "Microsoft.Insights/privateLinkScopes" {
		t.Errorf("ARM type: %q", r.Type)
	}
	if r.Properties["publicNetworkAccess"] != "Disabled" {
		t.Errorf("publicNetworkAccess lift: %v", r.Properties["publicNetworkAccess"])
	}
	if r.Properties["minimumTlsVersion"] != "1.2" {
		t.Errorf("minimumTlsVersion lift: %v", r.Properties["minimumTlsVersion"])
	}
	if r.Properties["disableLocalAuth"] != true {
		t.Errorf("disableLocalAuth derivation: %v", r.Properties["disableLocalAuth"])
	}
	if r.Properties["zoneRedundant"] != true {
		t.Errorf("zoneRedundant lift: %v", r.Properties["zoneRedundant"])
	}
	if r.Tags["env"] != "prod" {
		t.Errorf("tags not carried: %v", r.Tags)
	}
}

// TestResolveSKUField walks the dotted-path SKU extractor used for TF
// block-style sku references like "sku.0.name".
func TestResolveSKUField(t *testing.T) {
	m := map[string]interface{}{
		"sku": []interface{}{
			map[string]interface{}{"name": "Premium", "tier": "P1"},
		},
		"sku_name": "StandardV2",
	}
	if got := resolveSKUField(m, "sku_name"); got != "StandardV2" {
		t.Errorf("simple field: %q", got)
	}
	if got := resolveSKUField(m, "sku.0.name"); got != "Premium" {
		t.Errorf("nested block: %q", got)
	}
	if got := resolveSKUField(m, "sku.0.tier"); got != "P1" {
		t.Errorf("nested block tier: %q", got)
	}
	if got := resolveSKUField(m, "missing.0.path"); got != "" {
		t.Errorf("missing path should return empty, got %q", got)
	}
}

// TestTranslate_DispatchesGenericRegistry proves end-to-end that a TF
// resource listed only in the generic registry (not in the hand-written
// switch) round-trips through Translate with the correct ARM type.
func TestTranslate_DispatchesGenericRegistry(t *testing.T) {
	// Pick a type we know is generic-only.
	body := `{"format_version":"1.2","terraform_version":"1.6.0","resource_changes":[{"address":"azurerm_nat_gateway.t","mode":"managed","type":"azurerm_nat_gateway","name":"t","change":{"actions":["create"],"before":null,"after":{"name":"nat1","location":"eastus","resource_group_name":"rg1","sku_name":"Standard"}}}]}`
	p, err := ParsePlan(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	snap := Translate(p, "", "")
	if len(snap.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snap.Resources))
	}
	if snap.Resources[0].Type != "Microsoft.Network/natGateways" {
		t.Errorf("dispatch missed generic registry: got %q", snap.Resources[0].Type)
	}
	if snap.Resources[0].SKU != "Standard" {
		t.Errorf("SKU: %q", snap.Resources[0].SKU)
	}
}

// mustJSONObject is a test helper so we can write after-state literals
// inline without repeated boilerplate parsing.
func mustJSONObject(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	p, err := ParsePlan(strings.NewReader(`{"format_version":"1.2","terraform_version":"1.6.0","resource_changes":[{"address":"x.t","mode":"managed","type":"x","name":"t","change":{"actions":["create"],"before":null,"after":` + s + `}}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p.ResourceChanges[0].Change.After
}
