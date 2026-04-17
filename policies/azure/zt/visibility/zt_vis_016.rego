package argus.azure.zt.visibility.zt_vis_016

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_016",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Storage account access logging not enabled",
	"description": "Storage account diagnostic logs capture read, write, and delete operations. Without them, data exfiltration and tampering events cannot be detected or investigated.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-12",
	"cis_rule": "",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

has_diag(sa) if {
	rid := object.get(sa, "id", "")
	ds := object.get(input, "diagnostic_settings", {})
	object.get(ds, rid, false) == true
}

violation contains msg if {
	sa := input.storage_accounts[_]
	not has_diag(sa)
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sa, "id", ""),
		"resource_type": "Microsoft.Storage/storageAccounts",
		"resource_name": object.get(sa, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' has no diagnostic settings enabled. Data access events are not being logged.", [object.get(sa, "name", "")]),
		"evidence": {
			"storage_account_id": object.get(sa, "id", ""),
			"diagnostic_settings_enabled": false,
		},
		"chain_role": metadata.chain_role,
	}
}
