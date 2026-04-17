package argus.azure.zt.zt_data_024

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_024",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Redis Cache uses TLS < 1.2 or allows non-SSL port",
	"description": "Redis Cache with minimumTlsVersion below 1.2 or enableNonSslPort=true accepts traffic that downgrade-attackers can intercept. TLS 1.2+ and SSL-only mode are the baseline for every cache containing session tokens, cached PII, or precomputed authorization state.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - All communication is secured regardless of network location",
	"nist_800_53": "SC-8, SC-13",
	"cis_rule": "",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.cache/redis"
	props := object.get(resource, "properties", {})
	min_tls := object.get(props, "minimumTlsVersion", "1.0")
	min_tls != "1.2"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Redis Cache '%s' has minimumTlsVersion=%s. Set it to 1.2.", [resource.name, min_tls]),
		"evidence": {"minimumTlsVersion": min_tls},
		"chain_role": metadata.chain_role,
	}
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.cache/redis"
	props := object.get(resource, "properties", {})
	non_ssl := object.get(props, "enableNonSslPort", false)
	non_ssl == true

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": "HIGH",
		"title": "Redis Cache allows non-SSL port (6379 cleartext)",
		"detail": sprintf("Redis Cache '%s' has enableNonSslPort=true. Disable it so only port 6380 (TLS) is accepted.", [resource.name]),
		"evidence": {"enableNonSslPort": non_ssl},
		"chain_role": metadata.chain_role,
	}
}
