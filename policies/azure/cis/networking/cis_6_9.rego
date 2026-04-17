package argus.azure.cis.cis_6_9

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_9",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "Public IP addresses not associated with DDoS protection",
	"description": "Public IP addresses without DDoS protection are vulnerable to volumetric and protocol-level denial-of-service attacks that can render services unavailable.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-5",
	"cis_rule": "6.9",
	"mitre_technique": "T1498",
	"mitre_tactic": "Impact",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_ddos_protection(pip) if {
	ddos := object.get(object.get(pip, "properties", {}), "ddosSettings", {})
	object.get(ddos, "protectionMode", "") == "Enabled"
}

has_ddos_protection(pip) if {
	ddos := object.get(object.get(pip, "properties", {}), "ddosSettings", {})
	object.get(ddos, "protectedIP", false) == true
}

violation contains msg if {
	pip := input.public_ips[_]
	not has_ddos_protection(pip)
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(pip, "id", ""),
		"resource_type": "Microsoft.Network/publicIPAddresses",
		"resource_name": object.get(pip, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Public IP '%v' does not have DDoS protection enabled. This IP is vulnerable to denial-of-service attacks.", [object.get(pip, "name", "")]),
		"evidence": {
			"public_ip_id": object.get(pip, "id", ""),
			"ddos_protection": false,
		},
		"chain_role": metadata.chain_role,
	}
}
