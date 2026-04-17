package argus.azure.cis.cis_7_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_7_2",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Ensure encryption at host is enabled on VMs",
	"description": "Encryption at host encrypts data stored on the VM host including temp disks and OS/data disk caches. Without it, data may be written in plaintext to shared infrastructure.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - Per-session authenticated access",
	"nist_800_53": "SC-28(1)",
	"cis_rule": "7.2",
	"mitre_technique": "T1486",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	vm := input.virtual_machines[_]
	security_profile := object.get(vm.properties, "securityProfile", {})
	eah := object.get(security_profile, "encryptionAtHost", false)
	eah != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": vm.id,
		"resource_type": vm.type,
		"resource_name": vm.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VM '%v' does not have encryption at host enabled. Host cache and temp disk data may be unencrypted.", [vm.name]),
		"evidence": {
			"vm_id": vm.id,
			"encryption_at_host": eah,
		},
		"chain_role": metadata.chain_role,
	}
}
