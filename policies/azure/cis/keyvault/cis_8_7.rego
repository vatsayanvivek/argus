package argus.azure.cis.cis_8_7

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_8_7",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Key Vault uses private endpoint",
	"description": "Key Vaults accessible over the public internet expose secrets, keys, and certificates to network-based attacks. Private endpoints restrict access to the virtual network.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "8.7",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_private_endpoint(kv) if {
	pe := object.get(object.get(kv, "properties", {}), "privateEndpointConnections", [])
	count(pe) > 0
}

violation contains msg if {
	kv := input.key_vaults[_]
	not has_private_endpoint(kv)
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' does not use a private endpoint. Secrets are accessible over the public internet.", [kv.name]),
		"evidence": {
			"key_vault_id": kv.id,
			"private_endpoint_configured": false,
		},
		"chain_role": metadata.chain_role,
	}
}
