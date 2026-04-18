package engine

// fixtures_test.go is the shared builder library used by rule_coverage_test.go
// and chain_coverage_test.go to assemble synthetic AzureSnapshots without
// boilerplate struct literals.
//
// Pattern:
//
//     snap := newSnap().
//         withResource(nsgWithOpenInbound("web-nsg", "22", "*")).
//         withServicePrincipal(spWithNeverExpiringCred("backdoor-sp")).
//         withDefenderPlan("VirtualMachines", "Free").
//         build()
//     findings := runEngine(t, snap)
//     requireViolation(t, findings, "zt_id_001")
//
// When a new rule needs a kind of shape we don't have a helper for yet, add
// a focused helper here rather than inflating the table-driven test file.

import (
	"testing"
	"time"

	"github.com/vatsayanvivek/argus/internal/models"
)

// -----------------------------------------------------------------------------
// Snapshot builder
// -----------------------------------------------------------------------------

type snapBuilder struct {
	snap *models.AzureSnapshot
}

func newSnap() *snapBuilder {
	return &snapBuilder{
		snap: &models.AzureSnapshot{
			SubscriptionID:     "00000000-0000-0000-0000-000000000001",
			SubscriptionName:   "test-sub",
			TenantID:           "00000000-0000-0000-0000-0000000000ff",
			ScanTime:           time.Now(),
			DefenderPlans:      map[string]string{},
			DiagnosticSettings: map[string]bool{},
		},
	}
}

func (b *snapBuilder) withResource(r models.AzureResource) *snapBuilder {
	b.snap.Resources = append(b.snap.Resources, r)
	return b
}

func (b *snapBuilder) withServicePrincipal(sp models.ServicePrincipal) *snapBuilder {
	b.snap.Identity.ServicePrincipals = append(b.snap.Identity.ServicePrincipals, sp)
	return b
}

func (b *snapBuilder) withAppRegistration(app models.AppRegistration) *snapBuilder {
	b.snap.Identity.AppRegistrations = append(b.snap.Identity.AppRegistrations, app)
	return b
}

func (b *snapBuilder) withUser(u models.AADUser) *snapBuilder {
	b.snap.Identity.Users = append(b.snap.Identity.Users, u)
	return b
}

func (b *snapBuilder) withDefenderPlan(service, tier string) *snapBuilder {
	b.snap.DefenderPlans[service] = tier
	return b
}

func (b *snapBuilder) withNSG(nsg models.NetworkSecurityGroup) *snapBuilder {
	b.snap.NetworkTopology.NSGs = append(b.snap.NetworkTopology.NSGs, nsg)
	return b
}

func (b *snapBuilder) build() *models.AzureSnapshot {
	return b.snap
}

// -----------------------------------------------------------------------------
// Resource builders — NSG / network
// -----------------------------------------------------------------------------

// nsgWithOpenInbound produces a microsoft.network/networksecuritygroups resource
// carrying one inbound rule. Used by zt_net_001 / cis_6_1 violation fixtures.
func nsgWithOpenInbound(name, port, src string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.Network/networkSecurityGroups/" + name,
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

// -----------------------------------------------------------------------------
// Resource builders — Storage / Data
// -----------------------------------------------------------------------------

func publicBlobStorage(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.Storage/storageAccounts/" + name,
		Name: name,
		Type: "microsoft.storage/storageaccounts",
		Properties: map[string]interface{}{
			"allowBlobPublicAccess": true,
		},
	}
}

func privateBlobStorage(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.Storage/storageAccounts/" + name,
		Name: name,
		Type: "microsoft.storage/storageaccounts",
		Properties: map[string]interface{}{
			"allowBlobPublicAccess": false,
		},
	}
}

// -----------------------------------------------------------------------------
// Resource builders — Compute / Workload
// -----------------------------------------------------------------------------

func vmWithoutIdentity(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.Compute/virtualMachines/" + name,
		Name: name,
		Type: "microsoft.compute/virtualmachines",
		Properties: map[string]interface{}{
			"identity": map[string]interface{}{"type": "None"},
		},
	}
}

func vmWithSystemIdentity(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.Compute/virtualMachines/" + name,
		Name: name,
		Type: "microsoft.compute/virtualmachines",
		Properties: map[string]interface{}{
			"identity": map[string]interface{}{
				"type":        "SystemAssigned",
				"principalId": "11111111-1111-1111-1111-111111111111",
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Resource builders — AI / Cognitive Services
// -----------------------------------------------------------------------------

func cognitiveAcctPublic(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.CognitiveServices/accounts/" + name,
		Name: name,
		Type: "microsoft.cognitiveservices/accounts",
		Kind: "OpenAI",
		Properties: map[string]interface{}{
			"publicNetworkAccess": "Enabled",
		},
	}
}

func cognitiveAcctPrivate(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.CognitiveServices/accounts/" + name,
		Name: name,
		Type: "microsoft.cognitiveservices/accounts",
		Kind: "OpenAI",
		Properties: map[string]interface{}{
			"publicNetworkAccess": "Disabled",
		},
	}
}

// -----------------------------------------------------------------------------
// Resource builders — Integration / API Management
// -----------------------------------------------------------------------------

func apimWeakTLS(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.ApiManagement/service/" + name,
		Name: name,
		Type: "microsoft.apimanagement/service",
		Properties: map[string]interface{}{
			"customProperties": map[string]interface{}{
				"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10": "True",
			},
		},
	}
}

func apimStrongTLS(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.ApiManagement/service/" + name,
		Name: name,
		Type: "microsoft.apimanagement/service",
		Properties: map[string]interface{}{
			"customProperties": map[string]interface{}{
				"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10": "False",
				"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11": "False",
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Resource builders — Backup / Recovery Services
// -----------------------------------------------------------------------------

func recoveryVaultNoImmutability(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.RecoveryServices/vaults/" + name,
		Name: name,
		Type: "microsoft.recoveryservices/vaults",
		Properties: map[string]interface{}{
			"immutabilitySettings": map[string]interface{}{"state": "Disabled"},
		},
	}
}

func recoveryVaultImmutable(name string) models.AzureResource {
	return models.AzureResource{
		ID:   "/subscriptions/test/providers/Microsoft.RecoveryServices/vaults/" + name,
		Name: name,
		Type: "microsoft.recoveryservices/vaults",
		Properties: map[string]interface{}{
			"immutabilitySettings": map[string]interface{}{"state": "Locked"},
		},
	}
}

// -----------------------------------------------------------------------------
// Identity builders
// -----------------------------------------------------------------------------

// spWithNeverExpiringCred triggers zt_id_001. The rule accepts either null
// or a date string >= "2099" as a never-expiring credential. Because our
// Credential.EndDateTime is a Go string (zero value "" → JSON "", not JSON
// null), we use the far-future date form.
func spWithNeverExpiringCred(name string) models.ServicePrincipal {
	return models.ServicePrincipal{
		ID:          "/sp/" + name,
		DisplayName: name,
		AppID:       "12345678-1234-1234-1234-123456789012",
		PasswordCredentials: []models.Credential{
			{KeyID: "key-1", EndDateTime: "2099-12-31T00:00:00Z"},
		},
		AccountEnabled: true,
	}
}

func spWithExpiringCred(name string) models.ServicePrincipal {
	return models.ServicePrincipal{
		ID:          "/sp/" + name,
		DisplayName: name,
		AppID:       "12345678-1234-1234-1234-123456789012",
		PasswordCredentials: []models.Credential{
			{KeyID: "key-1", EndDateTime: "2025-06-01T00:00:00Z"},
		},
		AccountEnabled: true,
	}
}

// appWithPrivilegedGraphPerm is Microsoft Graph Application.ReadWrite.All as
// an application permission (Role = dangerous). Triggers zt_id_011.
func appWithPrivilegedGraphPerm(name string) models.AppRegistration {
	return models.AppRegistration{
		ID:          "/app/" + name,
		DisplayName: name,
		AppID:       "12345678-1234-1234-1234-123456789012",
		RequiredResourceAccess: []models.ResourceAccess{
			{
				ResourceAppID: "00000003-0000-0000-c000-000000000000", // Microsoft Graph
				Permissions: []models.Permission{
					{ID: "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", Type: "Role"},
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Engine harness
// -----------------------------------------------------------------------------

// runEngine prepares a fresh OPA engine and returns the findings list for a
// snapshot. Fatal on engine construction failure — caller should treat a
// nonzero-result list as "rules did fire", and branch on presence of a
// specific rule ID.
func runEngine(t *testing.T, snap *models.AzureSnapshot) []models.Finding {
	t.Helper()
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("NewOPAEngine: %v", err)
	}
	findings, err := engine.Evaluate(snap, "all")
	if err != nil {
		t.Fatalf("engine.Evaluate: %v", err)
	}
	return findings
}

// -----------------------------------------------------------------------------
// Assertions
// -----------------------------------------------------------------------------

// requireViolation fails the test unless at least one finding has the given
// rule ID.
func requireViolation(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s to fire, but it did not (findings=%d)", ruleID, len(findings))
}

// requireNoViolation fails the test if any finding carries the given rule ID.
func requireNoViolation(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == ruleID {
			t.Fatalf("expected rule %s to NOT fire, but it did: %+v", ruleID, f)
		}
	}
}
