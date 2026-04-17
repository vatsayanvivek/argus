package argus.azure.cis.cis_6_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_3",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Ensure UDP services are not exposed to the internet",
	"description": "Inbound UDP from the internet should be restricted. UDP services are common DDoS amplification vectors and often unauthenticated.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "SC-7",
	"cis_rule": "6.3",
	"mitre_technique": "T1498",
	"mitre_tactic": "Impact",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

internet_sources := {"*", "0.0.0.0/0", "Internet", "any"}

source_is_internet(rule) if {
	internet_sources[rule.properties.sourceAddressPrefix]
}

source_is_internet(rule) if {
	src := rule.properties.sourceAddressPrefixes[_]
	internet_sources[src]
}

violation contains msg if {
	nsg := input.network_security_groups[_]
	rule := nsg.properties.securityRules[_]
	rule.properties.direction == "Inbound"
	rule.properties.access == "Allow"
	rule.properties.protocol == "Udp"
	source_is_internet(rule)
	msg := {
		"rule_id": metadata.id,
		"resource_id": nsg.id,
		"resource_type": nsg.type,
		"resource_name": nsg.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("NSG '%v' rule '%v' allows inbound UDP from the internet on port(s) %v.", [nsg.name, rule.name, object.get(rule.properties, "destinationPortRange", "*")]),
		"evidence": {
			"nsg_id": nsg.id,
			"rule_name": rule.name,
			"protocol": "Udp",
			"source": object.get(rule.properties, "sourceAddressPrefix", ""),
			"destination_port": object.get(rule.properties, "destinationPortRange", ""),
		},
		"chain_role": metadata.chain_role,
	}
}
