package argus.azure.cis.cis_4_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_4_4",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Data",
	"title": "Ensure public network access is disabled for SQL servers",
	"description": "SQL servers should not be reachable from the public internet. Public access enables credential spraying, brute force, and exfiltration from compromised workloads.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "SC-7",
	"cis_rule": "4.4",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sql := input.sql_servers[_]
	pna := object.get(sql.properties, "publicNetworkAccess", "Enabled")
	pna != "Disabled"
	msg := {
		"rule_id": metadata.id,
		"resource_id": sql.id,
		"resource_type": sql.type,
		"resource_name": sql.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("SQL server '%v' has publicNetworkAccess='%v'. Move to private endpoints only.", [sql.name, pna]),
		"evidence": {
			"sql_server_id": sql.id,
			"public_network_access": pna,
		},
		"chain_role": metadata.chain_role,
	}
}
