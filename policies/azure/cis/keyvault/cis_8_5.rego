package argus.azure.cis.cis_8_5

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_8_5",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Key Vault secrets have expiration date set",
	"description": "Secrets without expiration dates can remain valid indefinitely. Setting expiration enforces credential rotation and limits the window of compromise for leaked secrets.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "IA-5",
	"cis_rule": "8.5",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	kv := input.key_vaults[_]
	secret := object.get(kv, "secrets", [])[_]
	attrs := object.get(secret, "attributes", {})
	not object.get(attrs, "expires", false)
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' secret '%v' has no expiration date set. The secret can remain valid indefinitely.", [kv.name, object.get(secret, "name", "")]),
		"evidence": {
			"key_vault_id": kv.id,
			"secret_name": object.get(secret, "name", ""),
			"expiration_set": false,
		},
		"chain_role": metadata.chain_role,
	}
}
