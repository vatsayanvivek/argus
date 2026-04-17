package argus.azure.cis.cis_6_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_2",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Network",
	"title": "Ensure RDP (port 3389) is not exposed to the internet",
	"description": "NSG inbound rules must not allow TCP port 3389 from '*' or '0.0.0.0/0'. Exposed RDP is the #1 cause of compromise for Azure Windows VMs.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication regardless of network location",
	"nist_800_53": "SC-7",
	"cis_rule": "6.2",
	"mitre_technique": "T1021.001",
	"mitre_tactic": "Lateral Movement",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

internet_sources := {"*", "0.0.0.0/0", "Internet", "any"}

matches_port_3389(rule) if {
	rule.properties.destinationPortRange == "3389"
}

matches_port_3389(rule) if {
	port := rule.properties.destinationPortRanges[_]
	port == "3389"
}

matches_port_3389(rule) if {
	rule.properties.destinationPortRange == "*"
}

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
	proto := object.get(rule.properties, "protocol", "*")
	proto != "Udp"
	matches_port_3389(rule)
	source_is_internet(rule)
	msg := {
		"rule_id": metadata.id,
		"resource_id": nsg.id,
		"resource_type": nsg.type,
		"resource_name": nsg.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("NSG '%v' rule '%v' allows inbound RDP from the internet. This exposes VMs to global brute force.", [nsg.name, rule.name]),
		"evidence": {
			"nsg_id": nsg.id,
			"rule_name": rule.name,
			"protocol": proto,
			"source": object.get(rule.properties, "sourceAddressPrefix", ""),
			"destination_port": object.get(rule.properties, "destinationPortRange", ""),
		},
		"chain_role": metadata.chain_role,
	}
}
