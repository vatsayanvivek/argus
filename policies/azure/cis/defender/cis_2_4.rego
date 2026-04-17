package argus.azure.cis.cis_2_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_4",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for Storage is set to Standard",
	"description": "Defender for Storage detects malware uploads, sensitive data exfiltration, and unusual access patterns on storage accounts.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Asset posture collection",
	"nist_800_53": "SI-4",
	"cis_rule": "2.4",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "storage_accounts", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "StorageAccounts",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for Storage is '%v' on subscription '%v'. Storage accounts lack malware scanning and exfiltration detection.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "storage_accounts",
		},
		"chain_role": metadata.chain_role,
	}
}
