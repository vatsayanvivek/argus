package argus.azure.cis.cis_7_8

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_7_8",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Virtual Machine managed disks use customer-managed keys",
	"description": "VM managed disks encrypted with platform-managed keys do not provide key rotation control. Customer-managed keys in Key Vault enable centralized key lifecycle management and revocation.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-28",
	"cis_rule": "7.8",
	"mitre_technique": "T1005",
	"mitre_tactic": "Collection",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

uses_cmk(vm) if {
	profile := object.get(object.get(vm, "properties", {}), "storageProfile", {})
	disk := object.get(profile, "osDisk", {})
	enc := object.get(object.get(disk, "managedDisk", {}), "diskEncryptionSet", {})
	object.get(enc, "id", "") != ""
}

violation contains msg if {
	vm := input.virtual_machines[_]
	not uses_cmk(vm)
	msg := {
		"rule_id": metadata.id,
		"resource_id": vm.id,
		"resource_type": vm.type,
		"resource_name": vm.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VM '%v' managed disks are not encrypted with customer-managed keys. Key rotation and revocation are not under organizational control.", [vm.name]),
		"evidence": {
			"vm_id": vm.id,
			"customer_managed_key": false,
		},
		"chain_role": metadata.chain_role,
	}
}
