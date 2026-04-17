package argus.azure.cis.cis_2_1_26

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1_26",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Defender for Azure Cosmos DB enabled",
	"description": "Defender for Cosmos DB detects SQL injection, suspicious access patterns, and potential data exfiltration from Cosmos DB accounts.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "2.1.26",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "cosmos_db", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "CosmosDb",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for Azure Cosmos DB is '%v' on subscription '%v'. Cosmos DB threats such as injection and exfiltration will not be detected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "cosmos_db",
		},
		"chain_role": metadata.chain_role,
	}
}
