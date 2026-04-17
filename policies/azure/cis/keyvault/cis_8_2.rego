package argus.azure.cis.cis_8_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_8_2",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Ensure Key Vault keys have rotation policies",
	"description": "Keys stored in Key Vault should have an automatic rotation policy configured so that cryptographic material does not stagnate.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Dynamic authentication",
	"nist_800_53": "SC-12",
	"cis_rule": "8.2",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	kv := input.key_vaults[_]
	rp := object.get(kv.properties, "rotation_policy", null)
	rp == null
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' has no key rotation policy configured. Keys will persist indefinitely without rotation.", [kv.name]),
		"evidence": {
			"key_vault_id": kv.id,
			"rotation_policy": "none",
		},
		"chain_role": metadata.chain_role,
	}
}
