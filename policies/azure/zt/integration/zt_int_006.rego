package argus.azure.zt.zt_int_006

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_006",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Front Door profile accepts TLS below 1.2",
	"description": "Front Door profiles with minimumTlsVersion below 1.2 negotiate weak ciphers with older clients, giving MITM attackers downgrade-attack opportunity against every origin behind the profile. Front Door is a public-internet accelerator — the TLS floor must be 1.2.",
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
	lower(resource.type) == "microsoft.cdn/profiles/afdendpoints"
	props := object.get(resource, "properties", {})
	min_tls := object.get(props, "minimumTlsVersion", "TLS10")
	min_tls != "TLS12"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Front Door endpoint '%s' has minimumTlsVersion=%s. Set it to TLS12.", [resource.name, min_tls]),
		"evidence": {"minimumTlsVersion": min_tls},
		"chain_role": metadata.chain_role,
	}
}
