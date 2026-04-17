package argus.azure.cis.cis_7_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_7_3",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Ensure VM data disks are encrypted",
	"description": "All VM data disks should be encrypted with either Azure Disk Encryption or server-side encryption with customer-managed keys.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - Per-session authenticated access",
	"nist_800_53": "SC-28(1)",
	"cis_rule": "7.3",
	"mitre_technique": "T1486",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	vm := input.virtual_machines[_]
	sp := object.get(vm.properties, "storageProfile", {})
	dd := object.get(sp, "dataDisks", [])
	disk := dd[_]
	encryption := object.get(disk, "encryptionSettings", {})
	enabled := object.get(encryption, "enabled", false)
	enabled != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": vm.id,
		"resource_type": vm.type,
		"resource_name": vm.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VM '%v' has unencrypted data disk '%v'. Stolen disks or snapshots can be read directly.", [vm.name, object.get(disk, "name", "unknown")]),
		"evidence": {
			"vm_id": vm.id,
			"disk_name": object.get(disk, "name", "unknown"),
			"disk_encrypted": enabled,
		},
		"chain_role": metadata.chain_role,
	}
}
