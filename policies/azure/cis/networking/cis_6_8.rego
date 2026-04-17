package argus.azure.cis.cis_6_8

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_8",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "NSG flow logs not enabled for all NSGs",
	"description": "NSG flow logs record all network traffic passing through a Network Security Group. Without flow logs, network-based lateral movement and data exfiltration cannot be detected.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "AU-12",
	"cis_rule": "6.8",
	"mitre_technique": "T1562.008",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_flow_log(nsg) if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.network/networkwatchers/flowlogs"
	target := object.get(object.get(r, "properties", {}), "targetResourceId", "")
	lower(target) == lower(object.get(nsg, "id", ""))
}

violation contains msg if {
	nsg := input.network_security_groups[_]
	not has_flow_log(nsg)
	msg := {
		"rule_id": metadata.id,
		"resource_id": nsg.id,
		"resource_type": nsg.type,
		"resource_name": nsg.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("NSG '%v' does not have flow logs enabled. Network traffic through this NSG is not being recorded.", [nsg.name]),
		"evidence": {
			"nsg_id": nsg.id,
			"flow_log_enabled": false,
		},
		"chain_role": metadata.chain_role,
	}
}
