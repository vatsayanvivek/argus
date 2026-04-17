package argus.azure.cis.cis_4_1

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_4_1",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Ensure 'Auditing' is set to On for SQL servers",
	"description": "SQL auditing tracks database events and writes them to an audit log for compliance and threat detection.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-2",
	"cis_rule": "4.1",
	"mitre_technique": "T1078",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sql := input.sql_servers[_]
	auditing := object.get(sql.properties, "auditingSettings", {})
	state := object.get(auditing, "state", "Disabled")
	state != "Enabled"
	msg := {
		"rule_id": metadata.id,
		"resource_id": sql.id,
		"resource_type": sql.type,
		"resource_name": sql.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("SQL server '%v' has auditing state '%v'. Database activity is not being logged.", [sql.name, state]),
		"evidence": {
			"sql_server_id": sql.id,
			"auditing_state": state,
		},
		"chain_role": metadata.chain_role,
	}
}
