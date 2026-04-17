package argus.azure.cis.cis_2_6

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_6",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for Key Vault is set to Standard",
	"description": "Defender for Key Vault detects anomalous secret and key access patterns that may indicate credential theft.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Asset posture collection",
	"nist_800_53": "SI-4",
	"cis_rule": "2.6",
	"mitre_technique": "T1555",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
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
		"detail": sprintf("Defender for Key Vault is '%v' on subscription '%v'. Vault access anomalies will go undetected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "key_vaults",
		},
		"chain_role": metadata.chain_role,
	}
}
