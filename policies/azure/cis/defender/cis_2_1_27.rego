package argus.azure.cis.cis_2_1_27

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1_27",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Defender for open-source relational databases enabled",
	"description": "Defender for open-source relational databases provides threat detection for PostgreSQL, MySQL, and MariaDB flexible servers including anomalous access and brute-force attacks.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "2.1.27",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "open_source_relational_databases", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "OpenSourceRelationalDatabases",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for open-source relational databases is '%v' on subscription '%v'. PostgreSQL, MySQL, and MariaDB threats will not be detected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "open_source_relational_databases",
		},
		"chain_role": metadata.chain_role,
	}
}
