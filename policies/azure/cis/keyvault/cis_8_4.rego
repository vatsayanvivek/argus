package argus.azure.cis.cis_8_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_8_4",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Ensure Key Vault uses private endpoints",
	"description": "Key Vaults should be accessible only via private endpoints so that secret retrieval traffic never crosses the public internet.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication regardless of network",
	"nist_800_53": "SC-7",
	"cis_rule": "8.4",
	"mitre_technique": "T1555",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	kv := input.key_vaults[_]
	pecs := object.get(kv.properties, "privateEndpointConnections", [])
	count(pecs) == 0
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' has no private endpoint connections. Secrets are reachable via public endpoint.", [kv.name]),
		"evidence": {
			"key_vault_id": kv.id,
			"private_endpoint_connections": 0,
		},
		"chain_role": metadata.chain_role,
	}
}
