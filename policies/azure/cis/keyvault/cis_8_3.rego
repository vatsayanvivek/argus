package argus.azure.cis.cis_8_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_8_3",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure Key Vault has diagnostic settings enabled",
	"description": "Key Vault should have diagnostic settings configured to stream audit events to a Log Analytics workspace or storage account.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-2",
	"cis_rule": "8.3",
	"mitre_technique": "T1555",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	kv := input.key_vaults[_]
	diag := object.get(input.diagnostic_settings, kv.id, false)
	diag != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": kv.id,
		"resource_type": kv.type,
		"resource_name": kv.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' has no diagnostic settings. Secret retrieval events are not audited.", [kv.name]),
		"evidence": {
			"key_vault_id": kv.id,
			"diagnostic_settings_enabled": diag,
		},
		"chain_role": metadata.chain_role,
	}
}
