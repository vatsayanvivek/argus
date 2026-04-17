package argus.azure.cis.cis_4_5

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_4_5",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Ensure 'Enforce SSL connection' is enabled for PostgreSQL",
	"description": "PostgreSQL flexible/single servers must enforce SSL so credentials and query data are encrypted in transit.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "SC-8(1)",
	"cis_rule": "4.5",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

is_postgres(srv) if {
	contains(lower(srv.type), "dbforpostgresql")
}

violation contains msg if {
	srv := input.sql_servers[_]
	is_postgres(srv)
	ssl := object.get(srv.properties, "sslEnforcement", "Disabled")
	ssl != "Enabled"
	msg := {
		"rule_id": metadata.id,
		"resource_id": srv.id,
		"resource_type": srv.type,
		"resource_name": srv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("PostgreSQL server '%v' has sslEnforcement='%v'. Clients can connect in plaintext.", [srv.name, ssl]),
		"evidence": {
			"server_id": srv.id,
			"ssl_enforcement": ssl,
		},
		"chain_role": metadata.chain_role,
	}
}
