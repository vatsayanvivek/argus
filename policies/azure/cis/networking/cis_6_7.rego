package argus.azure.cis.cis_6_7

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_7",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Azure Firewall Premium SKU not deployed",
	"description": "Azure Firewall Premium provides TLS inspection, IDPS, URL filtering, and web categories. Without it, encrypted malicious traffic passes uninspected through the network perimeter.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "6.7",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_premium_firewall if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.network/azurefirewalls"
	sku := object.get(object.get(r, "properties", {}), "sku", {})
	object.get(sku, "tier", "") == "Premium"
}

violation contains msg if {
	not has_premium_firewall
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.Network/azureFirewalls",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no Azure Firewall Premium SKU deployed. TLS inspection and IDPS capabilities are not available.", [object.get(sub, "display_name", "subscription")]),
		"evidence": {
			"premium_firewall_found": false,
		},
		"chain_role": metadata.chain_role,
	}
}
