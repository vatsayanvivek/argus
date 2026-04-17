package argus.azure.cis.cis_4_7

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_4_7",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "SQL Database has long-term backup retention configured",
	"description": "SQL Databases without long-term backup retention are vulnerable to data loss from ransomware or destructive attacks. Long-term retention ensures recovery beyond the default short-term window.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "CP-9",
	"cis_rule": "4.7",
	"mitre_technique": "T1486",
	"mitre_tactic": "Impact",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_ltr(srv) if {
	ltr := object.get(object.get(srv, "properties", {}), "longTermRetentionPolicy", {})
	weekly := object.get(ltr, "weeklyRetention", "")
	weekly != ""
	weekly != "PT0S"
}

has_ltr(srv) if {
	ltr := object.get(object.get(srv, "properties", {}), "longTermRetentionPolicy", {})
	monthly := object.get(ltr, "monthlyRetention", "")
	monthly != ""
	monthly != "PT0S"
}

has_ltr(srv) if {
	ltr := object.get(object.get(srv, "properties", {}), "longTermRetentionPolicy", {})
	yearly := object.get(ltr, "yearlyRetention", "")
	yearly != ""
	yearly != "PT0S"
}

violation contains msg if {
	srv := input.sql_servers[_]
	not has_ltr(srv)
	msg := {
		"rule_id": metadata.id,
		"resource_id": srv.id,
		"resource_type": srv.type,
		"resource_name": srv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("SQL Server '%v' does not have long-term backup retention configured. Data may be unrecoverable after ransomware or destructive attacks.", [srv.name]),
		"evidence": {
			"server_id": srv.id,
			"long_term_retention_configured": false,
		},
		"chain_role": metadata.chain_role,
	}
}
