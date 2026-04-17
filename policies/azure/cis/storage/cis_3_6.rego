package argus.azure.cis.cis_3_6

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_6",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Ensure soft delete is enabled for blob service",
	"description": "Blob soft delete protects against accidental or malicious deletion by retaining deleted blobs for a configurable period.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Continuous monitoring and recovery",
	"nist_800_53": "CP-9",
	"cis_rule": "3.6",
	"mitre_technique": "T1485",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	blob_props := object.get(sa.properties, "blobServiceProperties", {})
	dr := object.get(blob_props, "deleteRetentionPolicy", {})
	enabled := object.get(dr, "enabled", false)
	enabled != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' has blob soft delete disabled. Deleted blobs cannot be recovered.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"blob_delete_retention_enabled": enabled,
		},
		"chain_role": metadata.chain_role,
	}
}
