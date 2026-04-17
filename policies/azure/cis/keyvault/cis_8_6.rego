package argus.azure.cis.cis_8_6

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_8_6",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Key Vault keys have rotation policy configured",
	"description": "Keys without a rotation policy may remain static for extended periods. Automatic key rotation reduces the risk of key compromise and ensures cryptographic hygiene.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-12",
	"cis_rule": "8.6",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_rotation_policy(key) if {
	policy := object.get(key, "rotationPolicy", {})
	object.get(policy, "lifetimeActions", []) != []
}

violation contains msg if {
	kv := input.key_vaults[_]
	key := object.get(kv, "keys", [])[_]
	not has_rotation_policy(key)
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' key '%v' has no rotation policy configured. The key may remain static indefinitely.", [kv.name, object.get(key, "name", "")]),
		"evidence": {
			"key_vault_id": kv.id,
			"key_name": object.get(key, "name", ""),
			"rotation_policy_configured": false,
		},
		"chain_role": metadata.chain_role,
	}
}
