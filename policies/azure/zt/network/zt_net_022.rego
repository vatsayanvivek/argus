package argus.azure.zt.zt_net_022

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_net_022",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "Private DNS Zone has no virtual-network link — private endpoints unreachable",
	"description": "Private endpoints rely on Private DNS Zone VNet links to resolve <resource>.privatelink.<region>.<service> to the private endpoint IP. Without a VNet link, clients inside the VNet fall back to the public IP — defeating the private endpoint's entire purpose. Every Private DNS zone used for privatelink must be linked to the consuming VNets.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - All communication is secured regardless of network location",
	"nist_800_53": "SC-7",
	"cis_rule": "",
	"mitre_technique": "T1557.002",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.network/privatednszones"
	contains(lower(resource.name), "privatelink")
	props := object.get(resource, "properties", {})
	vnet_link_count := object.get(props, "numberOfVirtualNetworkLinks", 0)
	vnet_link_count == 0

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Private DNS zone '%s' (used for private-endpoint resolution) has zero VNet links. Clients will resolve to the public IP, bypassing the private endpoint.", [resource.name]),
		"evidence": {"numberOfVirtualNetworkLinks": vnet_link_count},
		"chain_role": metadata.chain_role,
	}
}
