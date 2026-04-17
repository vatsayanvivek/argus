package argus.azure.cis.cis_8_1

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_8_1",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Data",
	"title": "Ensure Key Vault has soft delete and purge protection enabled",
	"description": "Without soft delete or purge protection, an attacker with Contributor access to a Key Vault can irrecoverably destroy keys and secrets, breaking every service that depends on them.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - Per-session authenticated access",
	"nist_800_53": "CP-9",
	"cis_rule": "8.1",
	"mitre_technique": "T1485",
	"mitre_tactic": "Impact",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	kv := input.key_vaults[_]
	sd := object.get(kv.properties, "enableSoftDelete", false)
	sd == false
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' has soft delete disabled. Deleted keys and secrets cannot be recovered.", [kv.name]),
		"evidence": {
			"key_vault_id": kv.id,
			"enable_soft_delete": sd,
		},
		"chain_role": metadata.chain_role,
	}
}

violation contains msg if {
	kv := input.key_vaults[_]
	pp := object.get(kv.properties, "enablePurgeProtection", false)
	pp == false
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' has purge protection disabled. Soft-deleted items can be purged before retention ends.", [kv.name]),
		"evidence": {
			"key_vault_id": kv.id,
			"enable_purge_protection": pp,
		},
		"chain_role": metadata.chain_role,
	}
}
