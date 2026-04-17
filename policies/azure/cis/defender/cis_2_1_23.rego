package argus.azure.cis.cis_2_1_23

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1_23",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Defender for Key Vault not enabled",
	"description": "Defender for Key Vault detects unusual access patterns to secrets, keys, and certificates. Without it, credential theft from vaults will not trigger alerts.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "2.1.23",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "key_vaults", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "KeyVaults",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for Key Vault is '%v' on subscription '%v'. Unusual secret access patterns will not be detected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "key_vaults",
		},
		"chain_role": metadata.chain_role,
	}
}
