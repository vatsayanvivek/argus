package argus.azure.cis.cis_3_5

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_5",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Ensure storage accounts use private endpoints",
	"description": "Storage accounts should be reachable only via private endpoints so data plane traffic never traverses the public internet.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "SC-7",
	"cis_rule": "3.5",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	pecs := object.get(sa.properties, "privateEndpointConnections", [])
	count(pecs) == 0
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' has no private endpoint connections. Data is reachable via public endpoints.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"private_endpoint_connections": 0,
		},
		"chain_role": metadata.chain_role,
	}
}
