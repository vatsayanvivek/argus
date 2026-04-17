package argus.azure.cis.cis_3_7

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_7",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Ensure soft delete is enabled for containers",
	"description": "Container-level soft delete protects against accidental container deletion by retaining deleted containers for a configurable period.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Continuous monitoring and recovery",
	"nist_800_53": "CP-9",
	"cis_rule": "3.7",
	"mitre_technique": "T1485",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	blob_props := object.get(sa.properties, "blobServiceProperties", {})
	cdr := object.get(blob_props, "containerDeleteRetentionPolicy", {})
	enabled := object.get(cdr, "enabled", false)
	enabled != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' has container soft delete disabled. Deleted containers cannot be restored.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"container_delete_retention_enabled": enabled,
		},
		"chain_role": metadata.chain_role,
	}
}
