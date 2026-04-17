package argus.azure.cis.cis_2_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_3",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for SQL Servers is set to Standard",
	"description": "Defender for SQL detects anomalous queries, SQL injection, and brute force against Azure SQL.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Asset posture collection",
	"nist_800_53": "SI-4",
	"cis_rule": "2.3",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
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
		"detail": sprintf("Defender for SQL Servers is '%v' on subscription '%v'. SQL servers lack anomaly and injection detection.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "sql_servers",
		},
		"chain_role": metadata.chain_role,
	}
}
