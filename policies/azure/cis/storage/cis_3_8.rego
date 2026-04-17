package argus.azure.cis.cis_3_8

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_8",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure storage account diagnostic logs are enabled",
	"description": "Storage accounts should have diagnostic settings configured to capture read/write/delete operations for audit and detection.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-2",
	"cis_rule": "3.8",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	diag := object.get(input.diagnostic_settings, sa.id, false)
	diag != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' has no diagnostic settings. Data plane operations are not audited.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"diagnostic_settings_enabled": diag,
		},
		"chain_role": metadata.chain_role,
	}
}
