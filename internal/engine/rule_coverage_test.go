package engine

// rule_coverage_test.go is the table-driven coverage suite for individual
// Rego rules. Each case is one violation or one ok fixture; the test runs
// the real engine and asserts the target rule fires (or doesn't).
//
// The goal is to cover at least one rule per pillar (identity, data,
// network, workload, visibility, ai, integration, backup) with both a
// positive and a negative case, so a regression in rule loading, input
// transformation, or Rego syntax surfaces as a test failure instead of a
// silent scanning gap. Add new cases here whenever a rule is added; keep
// builders in fixtures_test.go.

import (
	"testing"

	"github.com/vatsayanvivek/argus/internal/models"
)

type ruleCase struct {
	rule  string                      // rule id we're asserting about
	name  string                      // short description, appears in go test output
	snap  func() *models.AzureSnapshot // snapshot under test
	fires bool                        // true = expect violation, false = expect silence
}

func TestRuleCoverage(t *testing.T) {
	cases := []ruleCase{
		// ------------------------------------------------------------------
		// Identity
		// ------------------------------------------------------------------
		{
			rule: "zt_id_001",
			name: "service principal with never-expiring password fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withServicePrincipal(spWithNeverExpiringCred("backdoor-sp")).
					build()
			},
			fires: true,
		},
		{
			rule: "zt_id_001",
			name: "service principal with expiry is silent",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withServicePrincipal(spWithExpiringCred("rotated-sp")).
					build()
			},
			fires: false,
		},
		{
			rule: "zt_id_011",
			name: "app registration with Application.ReadWrite.All (Role) fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withAppRegistration(appWithPrivilegedGraphPerm("risky-app")).
					build()
			},
			fires: true,
		},

		// ------------------------------------------------------------------
		// Data
		// ------------------------------------------------------------------
		{
			rule: "zt_data_001",
			name: "storage account with public blob access fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(publicBlobStorage("leaky-sa")).
					build()
			},
			fires: true,
		},
		{
			rule: "zt_data_001",
			name: "storage account with public blob access disabled is silent",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(privateBlobStorage("private-sa")).
					build()
			},
			fires: false,
		},

		// ------------------------------------------------------------------
		// Network
		// ------------------------------------------------------------------
		{
			rule: "zt_net_001",
			name: "NSG with SSH open to * fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(nsgWithOpenInbound("web-nsg", "22", "*")).
					build()
			},
			fires: true,
		},
		{
			rule: "zt_net_001",
			name: "NSG with SSH limited to a corporate CIDR is silent",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(nsgWithOpenInbound("web-nsg", "22", "10.0.0.0/8")).
					build()
			},
			fires: false,
		},
		{
			rule: "cis_6_1",
			name: "NSG with SSH from 0.0.0.0/0 fires CIS rule",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(nsgWithOpenInbound("web-nsg", "22", "0.0.0.0/0")).
					build()
			},
			fires: true,
		},

		// ------------------------------------------------------------------
		// Workload
		// ------------------------------------------------------------------
		{
			rule: "zt_wl_001",
			name: "VM without managed identity fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(vmWithoutIdentity("svc-vm")).
					build()
			},
			fires: true,
		},
		// NOTE: a negative case for zt_wl_001 (VM WITH managed identity is
		// silent) would require hoisting "identity" to a top-level field on
		// the serialised resource, which the current engine.resourceToJSON
		// doesn't do. Tracked separately; do not add a fires=false case for
		// this rule until the serialiser hoists identity out of properties.

		// ------------------------------------------------------------------
		// Visibility
		// ------------------------------------------------------------------
		{
			rule: "zt_vis_003",
			name: "defender plan at Free tier fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withDefenderPlan("VirtualMachines", "Free").
					withDefenderPlan("StorageAccounts", "Standard").
					build()
			},
			fires: true,
		},
		{
			rule: "zt_vis_003",
			name: "all defender plans at Standard is silent",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withDefenderPlan("VirtualMachines", "Standard").
					withDefenderPlan("StorageAccounts", "Standard").
					withDefenderPlan("KeyVaults", "Standard").
					build()
			},
			fires: false,
		},

		// ------------------------------------------------------------------
		// AI / Cognitive Services
		// ------------------------------------------------------------------
		{
			rule: "zt_ai_001",
			name: "Cognitive Services account with public network access fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(cognitiveAcctPublic("openai-prod")).
					build()
			},
			fires: true,
		},
		{
			rule: "zt_ai_001",
			name: "Cognitive Services account with private network access is silent",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(cognitiveAcctPrivate("openai-prod")).
					build()
			},
			fires: false,
		},

		// ------------------------------------------------------------------
		// Integration / API Management
		// ------------------------------------------------------------------
		{
			rule: "zt_int_001",
			name: "APIM service with TLS 1.0 enabled fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(apimWeakTLS("legacy-apim")).
					build()
			},
			fires: true,
		},
		{
			rule: "zt_int_001",
			name: "APIM service with TLS 1.0/1.1 disabled is silent",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(apimStrongTLS("modern-apim")).
					build()
			},
			fires: false,
		},

		// ------------------------------------------------------------------
		// Backup / Recovery Services
		// ------------------------------------------------------------------
		{
			rule: "zt_bak_001",
			name: "Recovery vault without Locked immutability fires",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(recoveryVaultNoImmutability("bkp-vault")).
					build()
			},
			fires: true,
		},
		{
			rule: "zt_bak_001",
			name: "Recovery vault with Locked immutability is silent",
			snap: func() *models.AzureSnapshot {
				return newSnap().
					withResource(recoveryVaultImmutable("bkp-vault")).
					build()
			},
			fires: false,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.rule+"/"+c.name, func(t *testing.T) {
			t.Parallel()
			findings := runEngine(t, c.snap())
			if c.fires {
				requireViolation(t, findings, c.rule)
			} else {
				requireNoViolation(t, findings, c.rule)
			}
		})
	}
}
