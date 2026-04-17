package argus.azure.zt.visibility.zt_vis_014

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_014",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Key Vault diagnostic logging not enabled",
	"description": "Key Vault diagnostic logs capture secret, key, and certificate access events. Without them, credential theft and misuse cannot be detected or investigated.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-12",
	"cis_rule": "",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

has_diag(kv) if {
	rid := object.get(kv, "id", "")
	ds := object.get(input, "diagnostic_settings", {})
	object.get(ds, rid, false) == true
}

violation contains msg if {
	kv := input.key_vaults[_]
	not has_diag(kv)
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(kv, "id", ""),
		"resource_type": "Microsoft.KeyVault/vaults",
		"resource_name": object.get(kv, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Key Vault '%v' has no diagnostic settings enabled. Secret and key access events are not being logged.", [object.get(kv, "name", "")]),
		"evidence": {
			"key_vault_id": object.get(kv, "id", ""),
			"diagnostic_settings_enabled": false,
		},
		"chain_role": metadata.chain_role,
	}
}
