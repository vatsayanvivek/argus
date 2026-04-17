package argus.azure.cis.cis_4_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_4_3",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Ensure SQL server Advanced Data Security is enabled",
	"description": "SQL security alert policies detect anomalous activities such as SQL injection and unusual access patterns.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "SI-4",
	"cis_rule": "4.3",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sql := input.sql_servers[_]
	sap := object.get(sql.properties, "securityAlertPolicies", {})
	state := object.get(sap, "state", "Disabled")
	state != "Enabled"
	msg := {
		"rule_id": metadata.id,
		"resource_id": sql.id,
		"resource_type": sql.type,
		"resource_name": sql.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("SQL server '%v' has security alert policies state '%v'. Anomalous activity will not generate alerts.", [sql.name, state]),
		"evidence": {
			"sql_server_id": sql.id,
			"security_alert_policies_state": state,
		},
		"chain_role": metadata.chain_role,
	}
}
