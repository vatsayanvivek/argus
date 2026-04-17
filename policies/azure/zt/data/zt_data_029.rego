package argus.azure.zt.zt_data_029

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_029",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "MariaDB server requires SSL or uses minimum TLS version 1.2",
	"description": "MariaDB for Azure servers with ssl_enforcement disabled accept unencrypted TCP connections — credentials and query payloads travel in cleartext. Even with SSL enforcement enabled, a minimum TLS version below 1.2 permits downgrade attacks on older clients. Require SSL and minimum TLS 1.2 for every server regardless of workload sensitivity.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - All communication is secured regardless of network location",
	"nist_800_53": "SC-8, SC-13",
	"cis_rule": "",
	"mitre_technique": "T1040",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.dbformariadb/servers"
	props := object.get(resource, "properties", {})
	ssl := object.get(props, "sslEnforcement", "Disabled")
	ssl != "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("MariaDB server '%s' has sslEnforcement=%s. Set it to 'Enabled'.", [resource.name, ssl]),
		"evidence": {"sslEnforcement": ssl},
		"chain_role": metadata.chain_role,
	}
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.dbformariadb/servers"
	props := object.get(resource, "properties", {})
	min_tls := object.get(props, "minimalTlsVersion", "TLS1_0")
	min_tls != "TLS1_2"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": "HIGH",
		"title": "MariaDB server accepts TLS below 1.2",
		"detail": sprintf("MariaDB server '%s' has minimalTlsVersion=%s. Set it to 'TLS1_2'.", [resource.name, min_tls]),
		"evidence": {"minimalTlsVersion": min_tls},
		"chain_role": metadata.chain_role,
	}
}
