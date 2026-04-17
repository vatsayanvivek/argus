package iac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These integration tests exercise argus iac against realistic plan
// JSON shaped to mimic what popular OSS Terraform modules produce when
// `terraform show -json plan.out` is run. They are not verbatim copies
// — the terraform registry does not expose plan JSON directly — but the
// resource structure and property names mirror the modules listed in
// each test's doc comment. The objective is a breadth-check: when
// a user runs argus iac against an Azure deployment built from one of
// these modules, the scanner should not crash and should emit a
// plausible set of findings at the expected severities.
//
// Adding a new fixture:
//   1. Build a realistic plan fragment as a Go raw string literal
//   2. Add a test that calls runOSSFixture and asserts the invariants
//      for that shape
//   3. Keep fixtures small — the goal is coverage of the translator +
//      policy engine wiring, not exhaustive realism.

// runOSSFixture writes the fixture JSON to a temp file and runs Scan
// against it, returning the Result for downstream assertion. Testing
// via the public Scan entry point (rather than Translate directly)
// ensures the full pipeline, including policy evaluation and in-plan
// filtering, behaves correctly.
func runOSSFixture(t *testing.T, name, planJSON string) *Result {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name+".plan.json")
	if err := os.WriteFile(path, []byte(planJSON), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	res, err := Scan(path, "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("Scan(%s): %v", name, err)
	}
	if res == nil || res.Snapshot == nil {
		t.Fatalf("Scan returned nil result")
	}
	return res
}

// countARMTypes returns how many distinct Microsoft.* ARM types the
// scanner emitted into the synthetic snapshot. Used as a breadth
// check — if a fixture lists 8 resources but the scanner only emits 3
// typed resources, something in the dispatch regressed.
func countARMTypes(res *Result) int {
	seen := map[string]struct{}{}
	for _, r := range res.Snapshot.Resources {
		if strings.HasPrefix(r.Type, "Microsoft.") {
			seen[r.Type] = struct{}{}
		}
	}
	return len(seen)
}

// findFindingIDs returns all finding IDs emitted by a Scan result, used
// to assert that specific rules fired for known-bad fixtures.
func findFindingIDs(res *Result) map[string]int {
	out := map[string]int{}
	for _, f := range res.Findings {
		out[f.ID]++
	}
	return out
}

// ossFixtureAKS mimics a plan produced from the Azure/terraform-azurerm-aks
// module pattern — a production-minded AKS cluster with private cluster
// enabled, ACR attached, Log Analytics for audit, and a Key Vault for
// secrets. This fixture is intentionally mostly well-configured so the
// test verifies the translator doesn't produce spurious findings
// against the happy path.
const ossFixtureAKS = `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "resource_changes": [
    {"address":"azurerm_kubernetes_cluster.this","mode":"managed","type":"azurerm_kubernetes_cluster","name":"this",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"aks-prod","location":"eastus","resource_group_name":"rg-aks",
       "private_cluster_enabled":true,
       "api_server_access_profile":[{"authorized_ip_ranges":["10.0.0.0/8"]}],
       "role_based_access_control_enabled":true,
       "azure_active_directory_role_based_access_control":[{"managed":true,"azure_rbac_enabled":true,"admin_group_object_ids":["00000000-0000-0000-0000-000000000001"]}],
       "network_profile":[{"network_plugin":"azure","network_policy":"calico"}],
       "azure_policy_enabled":true
     }}},
    {"address":"azurerm_container_registry.this","mode":"managed","type":"azurerm_container_registry","name":"this",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"acrprod","location":"eastus","resource_group_name":"rg-aks","sku":"Premium",
       "admin_enabled":false,"public_network_access_enabled":false,
       "zone_redundancy_enabled":true,"anonymous_pull_enabled":false
     }}},
    {"address":"azurerm_log_analytics_workspace.this","mode":"managed","type":"azurerm_log_analytics_workspace","name":"this",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"law-aks","location":"eastus","resource_group_name":"rg-aks",
       "retention_in_days":90,"sku":"PerGB2018","internet_ingestion_enabled":false,
       "local_authentication_disabled":true
     }}},
    {"address":"azurerm_key_vault.this","mode":"managed","type":"azurerm_key_vault","name":"this",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"kv-aks","location":"eastus","resource_group_name":"rg-aks",
       "purge_protection_enabled":true,"soft_delete_retention_days":90,
       "enable_rbac_authorization":true,"public_network_access_enabled":false,
       "network_acls":[{"default_action":"Deny","bypass":"AzureServices"}]
     }}}
  ]
}`

func TestOSSFixture_AKSBaseline(t *testing.T) {
	res := runOSSFixture(t, "aks_baseline", ossFixtureAKS)
	if got := len(res.Snapshot.Resources); got != 4 {
		t.Errorf("expected 4 translated resources, got %d", got)
	}
	if got := countARMTypes(res); got != 4 {
		t.Errorf("expected 4 distinct ARM types, got %d", got)
	}
	// A hardened AKS fixture should produce zero CRITICAL findings and
	// not crash the engine. We allow some MEDIUM/LOW because not every
	// best-practice knob is set, but a crash or a CRITICAL on a known-
	// good fixture is a regression.
	if res.Counts.Critical > 0 {
		ids := findFindingIDs(res)
		t.Errorf("hardened AKS fixture fired %d CRITICAL findings; IDs: %v", res.Counts.Critical, ids)
	}
}

// ossFixtureStorageInsecure mimics a bad plan: a storage account with
// allow_nested_items_to_be_public=true, no HTTPS-only, TLS 1.0,
// shared-key auth enabled, and public network access open. Should
// produce at least one CRITICAL or HIGH finding.
const ossFixtureStorageInsecure = `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "resource_changes": [
    {"address":"azurerm_storage_account.bad","mode":"managed","type":"azurerm_storage_account","name":"bad",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"stbad","location":"eastus","resource_group_name":"rg",
       "allow_nested_items_to_be_public":true,
       "enable_https_traffic_only":false,
       "min_tls_version":"TLS1_0",
       "public_network_access_enabled":true,
       "shared_access_key_enabled":true,
       "network_rules":[{"default_action":"Allow","bypass":["AzureServices"]}]
     }}},
    {"address":"azurerm_redis_cache.bad","mode":"managed","type":"azurerm_redis_cache","name":"bad",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"rediscache","location":"eastus","resource_group_name":"rg",
       "minimum_tls_version":"1.0","enable_non_ssl_port":true,
       "public_network_access_enabled":true,"sku_name":"Basic"
     }}}
  ]
}`

func TestOSSFixture_InsecureStorageAndRedis(t *testing.T) {
	res := runOSSFixture(t, "insecure_storage", ossFixtureStorageInsecure)
	if got := len(res.Snapshot.Resources); got != 2 {
		t.Errorf("expected 2 translated resources, got %d", got)
	}
	// The deliberately-insecure fixture must produce at least one
	// CRITICAL + HIGH finding. Exact IDs are brittle (the rule set
	// evolves), so we assert the severity bar instead.
	total := res.Counts.Critical + res.Counts.High
	if total == 0 {
		t.Errorf("insecure storage+redis plan should produce CRITICAL or HIGH findings, got 0 (%d medium, %d low)",
			res.Counts.Medium, res.Counts.Low)
	}
	// The storage account deliberately violates multiple rules — this
	// assertion guards that at least one rule binds to the synthesised
	// resource (i.e. the in-plan-scope filter in scanner.go is working).
	storageFindings := 0
	for _, f := range res.Findings {
		if strings.Contains(f.ResourceID, "azurerm_storage_account.bad") {
			storageFindings++
		}
	}
	if storageFindings == 0 {
		t.Errorf("expected storage findings against a public + TLS 1.0 + shared-key-enabled account; got 0")
	}
	// Verify Redis translator round-tripped correctly even though the
	// current rule set has no Redis-specific policies — shape check,
	// not finding count.
	var redisRes *string
	for i, r := range res.Snapshot.Resources {
		if r.Type == "Microsoft.Cache/Redis" {
			redisRes = &res.Snapshot.Resources[i].Name
			break
		}
	}
	if redisRes == nil {
		t.Errorf("Redis translator did not produce a Microsoft.Cache/Redis resource")
	}
}

// ossFixtureAppGatewayWAF mimics a plan for an internet-facing App
// Service behind Application Gateway with WAF in Detection mode (not
// Prevention), which is a common hardening gap. Also includes a
// Cognitive Services account that legitimately needs public access for
// a public API, mixed with a Bastion host configured with
// shareable_link_enabled=true (dangerous).
const ossFixtureAppGatewayWAF = `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "resource_changes": [
    {"address":"azurerm_linux_web_app.api","mode":"managed","type":"azurerm_linux_web_app","name":"api",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"app-api","location":"eastus","resource_group_name":"rg-web",
       "https_only":true,
       "site_config":[{"minimum_tls_version":"1.2","ftps_state":"Disabled","http2_enabled":true,"remote_debugging_enabled":false}]
     }}},
    {"address":"azurerm_application_gateway.waf","mode":"managed","type":"azurerm_application_gateway","name":"waf",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"agw-waf","location":"eastus","resource_group_name":"rg-web",
       "waf_configuration":[{"enabled":true,"firewall_mode":"Detection","rule_set_type":"OWASP","rule_set_version":"3.2"}],
       "ssl_policy":[{"policy_type":"Predefined","min_protocol_version":"TLSv1_2"}]
     }}},
    {"address":"azurerm_cognitive_account.openai","mode":"managed","type":"azurerm_cognitive_account","name":"openai",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"cog-openai","location":"eastus","resource_group_name":"rg-web","kind":"OpenAI","sku_name":"S0",
       "public_network_access_enabled":true,"custom_subdomain_name":"openai","local_auth_enabled":true
     }}},
    {"address":"azurerm_bastion_host.bastion","mode":"managed","type":"azurerm_bastion_host","name":"bastion",
     "change":{"actions":["create"],"before":null,"after":{
       "name":"bas-prod","location":"eastus","resource_group_name":"rg-web","sku":"Standard",
       "shareable_link_enabled":true,"tunneling_enabled":true
     }}}
  ]
}`

func TestOSSFixture_AppGatewayWithWAFDetection(t *testing.T) {
	res := runOSSFixture(t, "appgw_waf", ossFixtureAppGatewayWAF)
	if got := len(res.Snapshot.Resources); got != 4 {
		t.Errorf("expected 4 translated resources, got %d", got)
	}
	// WAF mode Detection is detection-only — rules that require
	// Prevention should fire at least MEDIUM. The assertion is
	// intentionally loose because the exact rule set evolves.
	if res.Counts.Critical+res.Counts.High+res.Counts.Medium == 0 {
		t.Errorf("WAF-in-detection fixture should produce at least one finding, got 0 (%d low)", res.Counts.Low)
	}
	// All three translators should round-trip: App Service, App
	// Gateway, Cognitive, Bastion.
	armTypes := map[string]bool{}
	for _, r := range res.Snapshot.Resources {
		armTypes[r.Type] = true
	}
	for _, want := range []string{
		"Microsoft.Web/sites",
		"Microsoft.Network/applicationGateways",
		"Microsoft.CognitiveServices/accounts",
		"Microsoft.Network/bastionHosts",
	} {
		if !armTypes[want] {
			t.Errorf("expected ARM type %q in snapshot, got: %v", want, keysOf(armTypes))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
