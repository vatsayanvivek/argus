package iac

import (
	"strconv"
	"strings"
	"testing"
)

const publicStoragePlan = `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "resource_changes": [
    {
      "address": "azurerm_storage_account.public",
      "mode": "managed",
      "type": "azurerm_storage_account",
      "name": "public",
      "provider_name": "registry.terraform.io/hashicorp/azurerm",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "name": "stpublic",
          "resource_group_name": "rg1",
          "location": "eastus",
          "allow_nested_items_to_be_public": true,
          "enable_https_traffic_only": false,
          "min_tls_version": "TLS1_0",
          "public_network_access_enabled": true,
          "shared_access_key_enabled": true,
          "network_rules": [{
            "default_action": "Allow",
            "bypass": ["AzureServices"]
          }],
          "blob_properties": [{
            "versioning_enabled": false
          }],
          "tags": {"env": "dev"}
        }
      }
    }
  ]
}`

func TestParsePlan_Minimal(t *testing.T) {
	p, err := ParsePlan(strings.NewReader(publicStoragePlan))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.FormatVersion != "1.2" {
		t.Errorf("format_version: got %q", p.FormatVersion)
	}
	if len(p.ResourceChanges) != 1 {
		t.Fatalf("resource_changes: expected 1, got %d", len(p.ResourceChanges))
	}
	rc := p.ResourceChanges[0]
	if rc.Type != "azurerm_storage_account" {
		t.Errorf("type: got %q", rc.Type)
	}
	if !rc.Change.IsCreateOrUpdate() {
		t.Error("expected create action to be treated as create-or-update")
	}
}

func TestParsePlan_RejectsNonPlan(t *testing.T) {
	_, err := ParsePlan(strings.NewReader(`{"not":"a plan"}`))
	if err == nil {
		t.Fatal("expected error for non-plan JSON")
	}
}

func TestTranslate_StorageAccount_MapsProperties(t *testing.T) {
	p, err := ParsePlan(strings.NewReader(publicStoragePlan))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	snap := Translate(p, "test-sub", "test-tenant")
	if len(snap.Resources) != 1 {
		t.Fatalf("resources: expected 1, got %d", len(snap.Resources))
	}
	sa := snap.Resources[0]
	if sa.Type != "Microsoft.Storage/storageAccounts" {
		t.Errorf("type: got %q", sa.Type)
	}
	if sa.Name != "stpublic" {
		t.Errorf("name: got %q", sa.Name)
	}
	if sa.ResourceGroup != "rg1" {
		t.Errorf("resource_group: got %q", sa.ResourceGroup)
	}
	if v := sa.Properties["allowBlobPublicAccess"]; v != true {
		t.Errorf("allowBlobPublicAccess: got %v (want true)", v)
	}
	if v := sa.Properties["supportsHttpsTrafficOnly"]; v != false {
		t.Errorf("supportsHttpsTrafficOnly: got %v (want false)", v)
	}
	if v := sa.Properties["minimumTlsVersion"]; v != "TLS1_0" {
		t.Errorf("minimumTlsVersion: got %v", v)
	}
	if v := sa.Properties["publicNetworkAccess"]; v != "Enabled" {
		t.Errorf("publicNetworkAccess: got %v", v)
	}
	if sa.Tags["env"] != "dev" {
		t.Errorf("tags not carried through: %v", sa.Tags)
	}
}

func TestTranslate_IgnoresDeletes(t *testing.T) {
	plan := strings.ReplaceAll(publicStoragePlan, `"actions": ["create"]`, `"actions": ["delete"]`)
	p, _ := ParsePlan(strings.NewReader(plan))
	snap := Translate(p, "", "")
	if len(snap.Resources) != 0 {
		t.Errorf("delete actions should be skipped, got %d resources", len(snap.Resources))
	}
}

func TestTranslate_KeyVault(t *testing.T) {
	kv := `{
      "format_version": "1.2",
      "terraform_version": "1.6.0",
      "resource_changes": [{
        "address": "azurerm_key_vault.vault",
        "mode": "managed",
        "type": "azurerm_key_vault",
        "name": "vault",
        "change": {
          "actions": ["create"],
          "before": null,
          "after": {
            "name": "kv-prod",
            "resource_group_name": "rg-prod",
            "location": "eastus",
            "purge_protection_enabled": false,
            "soft_delete_retention_days": 7,
            "enable_rbac_authorization": true,
            "public_network_access_enabled": false
          }
        }
      }]
    }`
	p, err := ParsePlan(strings.NewReader(kv))
	if err != nil {
		t.Fatal(err)
	}
	snap := Translate(p, "", "")
	if len(snap.Resources) != 1 || snap.Resources[0].Type != "Microsoft.KeyVault/vaults" {
		t.Fatalf("unexpected resources: %+v", snap.Resources)
	}
	props := snap.Resources[0].Properties
	if v := props["enablePurgeProtection"]; v != false {
		t.Errorf("enablePurgeProtection: %v", v)
	}
	if v := props["publicNetworkAccess"]; v != "Disabled" {
		t.Errorf("publicNetworkAccess: %v", v)
	}
	if v := props["enableRbacAuthorization"]; v != true {
		t.Errorf("enableRbacAuthorization: %v", v)
	}
}

func TestTranslate_NSGInboundRule(t *testing.T) {
	nsg := `{
      "format_version": "1.2",
      "terraform_version": "1.6.0",
      "resource_changes": [{
        "address": "azurerm_network_security_group.ssh",
        "mode": "managed",
        "type": "azurerm_network_security_group",
        "name": "ssh",
        "change": {
          "actions": ["create"],
          "before": null,
          "after": {
            "name": "nsg-ssh",
            "resource_group_name": "rg1",
            "location": "eastus",
            "security_rule": [{
              "name": "AllowSSH",
              "protocol": "Tcp",
              "direction": "Inbound",
              "access": "Allow",
              "priority": 100,
              "source_address_prefix": "*",
              "source_port_range": "*",
              "destination_address_prefix": "*",
              "destination_port_range": "22"
            }]
          }
        }
      }]
    }`
	p, _ := ParsePlan(strings.NewReader(nsg))
	snap := Translate(p, "", "")
	if len(snap.NetworkTopology.NSGs) != 1 {
		t.Fatalf("expected 1 NSG, got %d", len(snap.NetworkTopology.NSGs))
	}
	got := snap.NetworkTopology.NSGs[0]
	if len(got.InboundRules) != 1 {
		t.Fatalf("expected 1 inbound rule, got %d", len(got.InboundRules))
	}
	r := got.InboundRules[0]
	if r.SourceAddressPrefix != "*" || r.DestinationPortRange != "22" {
		t.Errorf("rule fields not carried through: %+v", r)
	}
}

// planJSON wraps a single-resource plan body in the minimal envelope
// ParsePlan requires — cuts noise in every per-type test below.
func planJSON(resourceType, address, afterJSON string) string {
	return `{
      "format_version": "1.2",
      "terraform_version": "1.6.0",
      "resource_changes": [{
        "address": "` + address + `",
        "mode": "managed",
        "type": "` + resourceType + `",
        "name": "t",
        "change": {
          "actions": ["create"],
          "before": null,
          "after": ` + afterJSON + `
        }
      }]
    }`
}

// translateOne runs Translate on a single-resource plan and returns the
// first (and only) AzureResource. It asserts resource count so tests
// don't silently pass on unexpected additions.
func translateOne(t *testing.T, resourceType, address, afterJSON, wantARMType string) (resource Rsrc) {
	t.Helper()
	p, err := ParsePlan(strings.NewReader(planJSON(resourceType, address, afterJSON)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	snap := Translate(p, "", "")
	if len(snap.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(snap.Resources))
	}
	if snap.Resources[0].Type != wantARMType {
		t.Fatalf("ARM type: got %q, want %q", snap.Resources[0].Type, wantARMType)
	}
	return Rsrc{
		Name: snap.Resources[0].Name,
		Type: snap.Resources[0].Type,
		Props: snap.Resources[0].Properties,
	}
}

type Rsrc struct {
	Name  string
	Type  string
	Props map[string]interface{}
}

func TestTranslate_PostgresFlexibleServer(t *testing.T) {
	r := translateOne(t, "azurerm_postgresql_flexible_server", "azurerm_postgresql_flexible_server.t",
		`{"name":"pgflex","location":"eastus","resource_group_name":"rg",
			"public_network_access_enabled":false,"administrator_login":"pgadmin","version":"15",
			"authentication":[{"active_directory_auth_enabled":true,"password_auth_enabled":false}]}`,
		"Microsoft.DBforPostgreSQL/flexibleServers")
	if r.Props["publicNetworkAccess"] != "Disabled" {
		t.Errorf("publicNetworkAccess: %v", r.Props["publicNetworkAccess"])
	}
	auth := r.Props["authConfig"].(map[string]interface{})
	if auth["activeDirectoryAuth"] != true || auth["passwordAuth"] != false {
		t.Errorf("auth config not mapped: %v", auth)
	}
}

func TestTranslate_MySQLFlexibleServer(t *testing.T) {
	r := translateOne(t, "azurerm_mysql_flexible_server", "azurerm_mysql_flexible_server.t",
		`{"name":"myflex","location":"eastus","resource_group_name":"rg",
			"public_network_access_enabled":true,"version":"8.0.21","backup_retention_days":14,
			"geo_redundant_backup_enabled":true}`,
		"Microsoft.DBforMySQL/flexibleServers")
	if r.Props["publicNetworkAccess"] != "Enabled" {
		t.Errorf("publicNetworkAccess: %v", r.Props["publicNetworkAccess"])
	}
	if r.Props["backupRetentionDays"] != 14 {
		t.Errorf("backupRetentionDays: %v", r.Props["backupRetentionDays"])
	}
	if r.Props["geoRedundantBackup"] != true {
		t.Errorf("geoRedundantBackup: %v", r.Props["geoRedundantBackup"])
	}
}

func TestTranslate_RedisCache(t *testing.T) {
	r := translateOne(t, "azurerm_redis_cache", "azurerm_redis_cache.t",
		`{"name":"cache","location":"eastus","resource_group_name":"rg",
			"minimum_tls_version":"1.2","enable_non_ssl_port":true,
			"public_network_access_enabled":true,"sku_name":"Basic"}`,
		"Microsoft.Cache/Redis")
	if r.Props["minimumTlsVersion"] != "1.2" {
		t.Errorf("tls: %v", r.Props["minimumTlsVersion"])
	}
	if r.Props["enableNonSslPort"] != true {
		t.Errorf("non-ssl port: %v", r.Props["enableNonSslPort"])
	}
}

func TestTranslate_ServiceBusNamespace(t *testing.T) {
	r := translateOne(t, "azurerm_servicebus_namespace", "azurerm_servicebus_namespace.t",
		`{"name":"sbns","location":"eastus","resource_group_name":"rg",
			"minimum_tls_version":"1.2","public_network_access_enabled":false,
			"local_auth_enabled":false,"sku":"Premium"}`,
		"Microsoft.ServiceBus/namespaces")
	if r.Props["publicNetworkAccess"] != "Disabled" {
		t.Errorf("publicNetworkAccess: %v", r.Props["publicNetworkAccess"])
	}
	if r.Props["localAuthEnabled"] != false {
		t.Errorf("localAuthEnabled: %v", r.Props["localAuthEnabled"])
	}
}

func TestTranslate_EventHubNamespace(t *testing.T) {
	r := translateOne(t, "azurerm_eventhub_namespace", "azurerm_eventhub_namespace.t",
		`{"name":"ehns","location":"eastus","resource_group_name":"rg",
			"minimum_tls_version":"1.2","public_network_access_enabled":true,
			"local_authentication_enabled":false,"zone_redundant":true,"sku":"Standard"}`,
		"Microsoft.EventHub/namespaces")
	if r.Props["localAuthEnabled"] != false {
		t.Errorf("localAuthEnabled: %v", r.Props["localAuthEnabled"])
	}
	if r.Props["zoneRedundant"] != true {
		t.Errorf("zoneRedundant: %v", r.Props["zoneRedundant"])
	}
}

func TestTranslate_LogAnalyticsWorkspace(t *testing.T) {
	r := translateOne(t, "azurerm_log_analytics_workspace", "azurerm_log_analytics_workspace.t",
		`{"name":"law","location":"eastus","resource_group_name":"rg",
			"retention_in_days":90,"internet_ingestion_enabled":false,
			"local_authentication_disabled":true,"sku":"PerGB2018"}`,
		"Microsoft.OperationalInsights/workspaces")
	if r.Props["retentionInDays"] != 90 {
		t.Errorf("retentionInDays: %v", r.Props["retentionInDays"])
	}
	if r.Props["internetIngestionEnabled"] != false {
		t.Errorf("internetIngestionEnabled: %v", r.Props["internetIngestionEnabled"])
	}
}

func TestTranslate_ApplicationGateway_WAF(t *testing.T) {
	r := translateOne(t, "azurerm_application_gateway", "azurerm_application_gateway.t",
		`{"name":"agw","location":"eastus","resource_group_name":"rg",
			"waf_configuration":[{"enabled":true,"firewall_mode":"Prevention",
				"rule_set_type":"OWASP","rule_set_version":"3.2"}],
			"ssl_policy":[{"policy_type":"Predefined","min_protocol_version":"TLSv1_2"}]}`,
		"Microsoft.Network/applicationGateways")
	waf := r.Props["webApplicationFirewallConfiguration"].(map[string]interface{})
	if waf["enabled"] != true || waf["firewallMode"] != "Prevention" {
		t.Errorf("waf not mapped: %v", waf)
	}
	tls := r.Props["sslPolicy"].(map[string]interface{})
	if tls["minProtocolVersion"] != "TLSv1_2" {
		t.Errorf("tls min version: %v", tls)
	}
}

func TestTranslate_AzureFirewall(t *testing.T) {
	r := translateOne(t, "azurerm_firewall", "azurerm_firewall.t",
		`{"name":"afw","location":"eastus","resource_group_name":"rg",
			"threat_intel_mode":"Alert","sku_name":"AZFW_VNet","sku_tier":"Premium"}`,
		"Microsoft.Network/azureFirewalls")
	if r.Props["threatIntelMode"] != "Alert" {
		t.Errorf("threatIntelMode: %v", r.Props["threatIntelMode"])
	}
	if r.Props["skuTier"] != "Premium" {
		t.Errorf("skuTier: %v", r.Props["skuTier"])
	}
}

func TestTranslate_BastionHost(t *testing.T) {
	r := translateOne(t, "azurerm_bastion_host", "azurerm_bastion_host.t",
		`{"name":"bas","location":"eastus","resource_group_name":"rg",
			"sku":"Standard","tunneling_enabled":true,"shareable_link_enabled":true}`,
		"Microsoft.Network/bastionHosts")
	if r.Props["tunnelingEnabled"] != true {
		t.Errorf("tunnelingEnabled: %v", r.Props["tunnelingEnabled"])
	}
	if r.Props["shareableLinkEnabled"] != true {
		t.Errorf("shareableLinkEnabled: %v", r.Props["shareableLinkEnabled"])
	}
}

func TestTranslate_CognitiveAccount(t *testing.T) {
	r := translateOne(t, "azurerm_cognitive_account", "azurerm_cognitive_account.t",
		`{"name":"cog","location":"eastus","resource_group_name":"rg","kind":"OpenAI",
			"public_network_access_enabled":false,"custom_subdomain_name":"myopenai",
			"local_auth_enabled":false,"sku_name":"S0"}`,
		"Microsoft.CognitiveServices/accounts")
	if r.Props["publicNetworkAccess"] != "Disabled" {
		t.Errorf("publicNetworkAccess: %v", r.Props["publicNetworkAccess"])
	}
	// disableLocalAuth is a boolean derived from !local_auth_enabled
	if r.Props["disableLocalAuth"] != true {
		t.Errorf("disableLocalAuth: %v", r.Props["disableLocalAuth"])
	}
}

func TestTranslate_ManagedDisk(t *testing.T) {
	r := translateOne(t, "azurerm_managed_disk", "azurerm_managed_disk.t",
		`{"name":"disk1","location":"eastus","resource_group_name":"rg",
			"os_type":"Linux","disk_size_gb":64,"storage_account_type":"Premium_LRS",
			"public_network_access_enabled":false,"network_access_policy":"DenyAll"}`,
		"Microsoft.Compute/disks")
	if r.Props["networkAccessPolicy"] != "DenyAll" {
		t.Errorf("networkAccessPolicy: %v", r.Props["networkAccessPolicy"])
	}
	if r.Props["diskSizeGB"] != 64 {
		t.Errorf("diskSizeGB: %v", r.Props["diskSizeGB"])
	}
}

func TestTranslate_RecoveryServicesVault(t *testing.T) {
	r := translateOne(t, "azurerm_recovery_services_vault", "azurerm_recovery_services_vault.t",
		`{"name":"rsv","location":"eastus","resource_group_name":"rg",
			"soft_delete_enabled":true,"cross_region_restore_enabled":true,
			"public_network_access_enabled":false,"immutability":"Locked","sku":"Standard"}`,
		"Microsoft.RecoveryServices/vaults")
	if r.Props["softDeleteEnabled"] != true {
		t.Errorf("softDeleteEnabled: %v", r.Props["softDeleteEnabled"])
	}
	if r.Props["immutability"] != "Locked" {
		t.Errorf("immutability: %v", r.Props["immutability"])
	}
}

func TestTranslate_NetworkWatcher(t *testing.T) {
	r := translateOne(t, "azurerm_network_watcher", "azurerm_network_watcher.t",
		`{"name":"nw1","location":"eastus","resource_group_name":"rg"}`,
		"Microsoft.Network/networkWatchers")
	if r.Name != "nw1" {
		t.Errorf("name: %q", r.Name)
	}
}

func TestTranslate_VirtualNetworkGateway(t *testing.T) {
	r := translateOne(t, "azurerm_virtual_network_gateway", "azurerm_virtual_network_gateway.t",
		`{"name":"vng","location":"eastus","resource_group_name":"rg",
			"type":"Vpn","vpn_type":"RouteBased","active_active":true,"sku":"VpnGw2","generation":"Generation2"}`,
		"Microsoft.Network/virtualNetworkGateways")
	if r.Props["activeActive"] != true {
		t.Errorf("activeActive: %v", r.Props["activeActive"])
	}
	if r.Props["generation"] != "Generation2" {
		t.Errorf("generation: %v", r.Props["generation"])
	}
}

func TestTranslate_ContainerApp_Ingress(t *testing.T) {
	r := translateOne(t, "azurerm_container_app", "azurerm_container_app.t",
		`{"name":"ca1","location":"eastus","resource_group_name":"rg",
			"ingress":[{"external_enabled":true,"allow_insecure_connections":true,"target_port":8080,"transport":"http"}],
			"identity":[{"type":"SystemAssigned"}],"revision_mode":"Single"}`,
		"Microsoft.App/containerApps")
	cfg := r.Props["configuration"].(map[string]interface{})
	ing := cfg["ingress"].(map[string]interface{})
	if ing["external"] != true || ing["allowInsecure"] != true {
		t.Errorf("ingress not mapped: %v", ing)
	}
}

func TestTranslate_SearchService(t *testing.T) {
	r := translateOne(t, "azurerm_search_service", "azurerm_search_service.t",
		`{"name":"search","location":"eastus","resource_group_name":"rg",
			"public_network_access_enabled":false,"local_authentication_enabled":false,
			"replica_count":2,"partition_count":3,"sku":"standard"}`,
		"Microsoft.Search/searchServices")
	if r.Props["publicNetworkAccess"] != "Disabled" {
		t.Errorf("publicNetworkAccess: %v", r.Props["publicNetworkAccess"])
	}
	if r.Props["localAuthenticationEnabled"] != false {
		t.Errorf("localAuthenticationEnabled: %v", r.Props["localAuthenticationEnabled"])
	}
}

// TestTranslate_CountsAllCoveredTypes is a canary: if someone adds a
// case in the dispatch switch but forgets the corresponding per-type
// test, this test will still pass — it only checks dispatch, not
// mapping quality. Its job is to guard the coverage surface: total
// number of azurerm_* TF types the translator understands.
func TestTranslate_CountsAllCoveredTypes(t *testing.T) {
	// Every distinct TF type we dispatch (counting aliases separately).
	// Update this list and the number when adding new types.
	tfTypes := []string{
		"azurerm_storage_account",
		"azurerm_key_vault",
		"azurerm_mssql_server", "azurerm_sql_server",
		"azurerm_postgresql_server", "azurerm_postgresql_flexible_server",
		"azurerm_mysql_server", "azurerm_mysql_flexible_server",
		"azurerm_cosmosdb_account",
		"azurerm_kubernetes_cluster",
		"azurerm_container_registry",
		"azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app",
		"azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app",
		"azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine",
		"azurerm_public_ip",
		"azurerm_network_security_group",
		"azurerm_virtual_network",
		"azurerm_subnet",
		"azurerm_redis_cache",
		"azurerm_servicebus_namespace",
		"azurerm_eventhub_namespace",
		"azurerm_log_analytics_workspace",
		"azurerm_application_gateway",
		"azurerm_frontdoor", "azurerm_cdn_frontdoor_profile",
		"azurerm_firewall",
		"azurerm_bastion_host",
		"azurerm_cognitive_account",
		"azurerm_managed_disk",
		"azurerm_recovery_services_vault",
		"azurerm_network_watcher",
		"azurerm_virtual_network_gateway",
		"azurerm_container_app",
		"azurerm_search_service",
	}
	// Canonical ARM-type count (dedupe across TF aliases).
	// 30 distinct Microsoft.* ARM types after P3. If this drifts,
	// either coverage shrank (regression) or expanded — update this
	// guard consciously, don't just bump the number.
	// Note: this test only counts hand-written translator dispatch;
	// the generic-registry coverage is asserted by
	// TestGenericRegistry_CountsOver150Types.
	const expectedARMTypes = 30
	if len(tfTypes) < 38 {
		t.Errorf("translator coverage shrank: %d TF types listed (expected >= 38)", len(tfTypes))
	}
	// Build a plan with one of every TF type, translate it, count
	// distinct ARM types.
	rcs := make([]string, 0, len(tfTypes))
	for i, tp := range tfTypes {
		rcs = append(rcs, `{"address":"`+tp+`.t","mode":"managed","type":"`+tp+`","name":"r`+stringFromInt(i)+`","change":{"actions":["create"],"before":null,"after":{"name":"n`+stringFromInt(i)+`","location":"eastus","resource_group_name":"rg"}}}`)
	}
	plan := `{"format_version":"1.2","terraform_version":"1.6.0","resource_changes":[` + strings.Join(rcs, ",") + `]}`
	p, err := ParsePlan(strings.NewReader(plan))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	snap := Translate(p, "", "")
	armTypes := map[string]struct{}{}
	for _, r := range snap.Resources {
		armTypes[r.Type] = struct{}{}
	}
	// Subnet lives on NetworkTopology, not Resources — add its synthetic ARM type manually.
	if len(snap.NetworkTopology.Subnets) > 0 {
		armTypes["Microsoft.Network/virtualNetworks/subnets"] = struct{}{}
	}
	// azurerm_frontdoor and azurerm_cdn_frontdoor_profile both map to the same ARM type,
	// azurerm_app_service/linux_web_app/windows_web_app to the same, etc. Dedupe happens automatically.
	microsoftTypes := 0
	for k := range armTypes {
		if strings.HasPrefix(k, "Microsoft.") {
			microsoftTypes++
		}
	}
	if microsoftTypes < expectedARMTypes {
		t.Errorf("expected at least %d Microsoft.* ARM types covered, got %d: %v",
			expectedARMTypes, microsoftTypes, armTypes)
	}
}

// stringFromInt returns the decimal representation of i. Kept as a
// tiny helper so the JSON-building loops above read cleanly.
func stringFromInt(i int) string {
	return strconv.Itoa(i)
}

func TestGateTripped(t *testing.T) {
	c := SeverityCounts{Critical: 0, High: 1, Medium: 2, Low: 3}
	cases := []struct {
		floor    string
		expected bool
	}{
		{"CRITICAL", false},
		{"HIGH", true},
		{"MEDIUM", true},
		{"LOW", true},
		{"NONE", false},
	}
	for _, tc := range cases {
		got := gateTrippedHelper(c, tc.floor)
		if got != tc.expected {
			t.Errorf("floor=%s: got %v, want %v", tc.floor, got, tc.expected)
		}
	}
}

// gateTrippedHelper mirrors the logic in cmd/iac.go for unit testing
// without creating a dependency from the iac package on the cmd package.
func gateTrippedHelper(c SeverityCounts, floor string) bool {
	switch strings.ToUpper(floor) {
	case "CRITICAL":
		return c.Critical > 0
	case "HIGH":
		return c.Critical+c.High > 0
	case "MEDIUM":
		return c.Critical+c.High+c.Medium > 0
	case "LOW":
		return c.Critical+c.High+c.Medium+c.Low > 0
	case "NONE", "":
		return false
	default:
		return c.Critical+c.High > 0
	}
}
