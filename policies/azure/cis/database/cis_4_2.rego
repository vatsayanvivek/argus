package argus.azure.cis.cis_4_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_4_2",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Ensure Transparent Data Encryption is enabled on SQL databases",
	"description": "TDE encrypts SQL databases at rest. Without TDE, stolen backups or database files can be read directly.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - Per-session authenticated access",
	"nist_800_53": "SC-28(1)",
	"cis_rule": "4.2",
	"mitre_technique": "T1486",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sql := input.sql_servers[_]
	tde := object.get(sql.properties, "transparentDataEncryption", {})
	status := object.get(tde, "status", "Disabled")
	status != "Enabled"
	msg := {
		"rule_id": metadata.id,
		"resource_id": sql.id,
		"resource_type": sql.type,
		"resource_name": sql.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("SQL server '%v' has TDE status '%v'. Database files are unencrypted at rest.", [sql.name, status]),
		"evidence": {
			"sql_server_id": sql.id,
			"tde_status": status,
		},
		"chain_role": metadata.chain_role,
	}
}
