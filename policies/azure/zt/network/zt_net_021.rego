package argus.azure.zt.zt_net_021

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_net_021",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "VPN Gateway uses a deprecated Basic SKU",
	"description": "VPN Gateway Basic SKU is end-of-life for commercial use as of Q3 2025. Basic gateways lack BGP support, active-active failover, and the modern IKEv2 cipher suite. Workloads still on Basic should migrate to VpnGw1/2/3 (or ErGw1AZ for ExpressRoute). Basic will stop receiving security patches.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "SC-8",
	"cis_rule": "",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.network/virtualnetworkgateways"
	sku := object.get(resource, "sku", "")
	contains_basic_sku(sku)

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VPN Gateway '%s' uses deprecated Basic SKU. Migrate to VpnGw1 or higher.", [resource.name]),
		"evidence": {"sku": sku},
		"chain_role": metadata.chain_role,
	}
}

contains_basic_sku(sku) if {
	lower(sku) == "basic"
}
