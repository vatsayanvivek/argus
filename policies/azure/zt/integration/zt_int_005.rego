package argus.azure.zt.zt_int_005

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_005",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "Traffic Manager profile uses HTTP (not HTTPS) for probes",
	"description": "Traffic Manager profiles with monitorProtocol=HTTP probe the endpoints over cleartext. The probe carries no auth secrets, but an attacker who can MITM the probe traffic can forge healthy responses for an unhealthy endpoint or vice versa — flipping traffic to their rogue endpoint. Use HTTPS probes for any Traffic Manager profile fronting internet-accessible services.",
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
	lower(resource.type) == "microsoft.network/trafficmanagerprofiles"
	props := object.get(resource, "properties", {})
	monitor := object.get(props, "monitorConfig", {})
	proto := object.get(monitor, "protocol", "HTTP")
	proto != "HTTPS"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Traffic Manager profile '%s' uses monitorProtocol=%s. Switch to HTTPS probes.", [resource.name, proto]),
		"evidence": {"monitorProtocol": proto},
		"chain_role": metadata.chain_role,
	}
}
