package argus.azure.cis.cis_3_16

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_16",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Storage account uses private endpoints",
	"description": "Storage accounts accessible over the public internet expose data to network-based attacks. Private endpoints restrict access to the virtual network and eliminate public exposure.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "3.16",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_private_endpoint(sa) if {
	pe := object.get(object.get(sa, "properties", {}), "privateEndpointConnections", [])
	count(pe) > 0
}

violation contains msg if {
	sa := input.storage_accounts[_]
	not has_private_endpoint(sa)
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' does not use private endpoints. Data is accessible over the public internet.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"private_endpoint_configured": false,
		},
		"chain_role": metadata.chain_role,
	}
}
