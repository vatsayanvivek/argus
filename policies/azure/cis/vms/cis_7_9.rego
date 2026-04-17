package argus.azure.cis.cis_7_9

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_7_9",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Unattached disks are encrypted with customer-managed key",
	"description": "Unattached managed disks may still contain sensitive data. Encrypting them with customer-managed keys ensures data remains protected even when disks are detached from VMs.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-28",
	"cis_rule": "7.9",
	"mitre_technique": "T1005",
	"mitre_tactic": "Collection",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.compute/disks"
	object.get(object.get(r, "properties", {}), "diskState", "") == "Unattached"
	enc := object.get(object.get(r, "properties", {}), "encryption", {})
	object.get(enc, "type", "") != "EncryptionAtRestWithCustomerKey"
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(r, "id", ""),
		"resource_type": "Microsoft.Compute/disks",
		"resource_name": object.get(r, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Unattached disk '%v' is not encrypted with a customer-managed key. Data on this disk is not under organizational key control.", [object.get(r, "name", "")]),
		"evidence": {
			"disk_id": object.get(r, "id", ""),
			"disk_state": "Unattached",
			"encryption_type": object.get(enc, "type", ""),
		},
		"chain_role": metadata.chain_role,
	}
}
