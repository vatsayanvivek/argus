package argus.azure.cis.cis_2_1_28

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1_28",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Defender for Azure SQL Database enabled",
	"description": "Defender for Azure SQL Database detects SQL injection, anomalous access, and brute-force attacks against Azure SQL databases. Without it, database-layer attacks go undetected.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "2.1.28",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "sql_servers", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "SqlServers",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for Azure SQL Database is '%v' on subscription '%v'. SQL injection and brute-force attacks will not be detected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "sql_servers",
		},
		"chain_role": metadata.chain_role,
	}
}
