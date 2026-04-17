package argus.azure.cis.cis_4_6

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_4_6",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Identity",
	"title": "SQL Server uses Azure AD-only authentication",
	"description": "SQL Servers that allow local SQL authentication alongside Azure AD are vulnerable to password-based attacks. Azure AD-only authentication enforces MFA, conditional access, and centralized identity governance.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "IA-2",
	"cis_rule": "4.6",
	"mitre_technique": "T1078",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

is_sql_server(srv) if {
	contains(lower(object.get(srv, "type", "")), "microsoft.sql/servers")
	not contains(lower(object.get(srv, "type", "")), "dbformysql")
	not contains(lower(object.get(srv, "type", "")), "dbforpostgresql")
	not contains(lower(object.get(srv, "type", "")), "dbformariadb")
}

violation contains msg if {
	srv := input.sql_servers[_]
	is_sql_server(srv)
	aad_only := object.get(object.get(srv, "properties", {}), "azureADOnlyAuthentication", false)
	aad_only != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": srv.id,
		"resource_type": srv.type,
		"resource_name": srv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("SQL Server '%v' does not enforce Azure AD-only authentication. Local SQL authentication allows password-based attacks that bypass MFA and conditional access.", [srv.name]),
		"evidence": {
			"server_id": srv.id,
			"azure_ad_only_authentication": aad_only,
		},
		"chain_role": metadata.chain_role,
	}
}
