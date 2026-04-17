package argus.azure.cis.cis_7_10

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_7_10",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Workload",
	"title": "Only approved VM extensions are installed",
	"description": "VM extensions execute code with elevated privileges on the host. Unapproved extensions can be used for persistence, privilege escalation, or command execution.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "CM-7",
	"cis_rule": "7.10",
	"mitre_technique": "T1059",
	"mitre_tactic": "Execution",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

approved_extensions := {
	"MicrosoftMonitoringAgent",
	"OmsAgentForLinux",
	"AzureMonitorWindowsAgent",
	"AzureMonitorLinuxAgent",
	"DependencyAgentWindows",
	"DependencyAgentLinux",
	"AzureDiskEncryption",
	"AzureDiskEncryptionForLinux",
	"MDE.Windows",
	"MDE.Linux",
	"GuestAttestation",
}

violation contains msg if {
	vm := input.virtual_machines[_]
	ext := object.get(vm, "extensions", [])
	e := ext[_]
	ename := object.get(e, "name", "")
	not approved_extensions[ename]
	msg := {
		"rule_id": metadata.id,
		"resource_id": vm.id,
		"resource_type": vm.type,
		"resource_name": vm.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VM '%v' has unapproved extension '%v' installed. Unapproved extensions can execute arbitrary code with elevated privileges.", [vm.name, ename]),
		"evidence": {
			"vm_id": vm.id,
			"extension_name": ename,
			"approved": false,
		},
		"chain_role": metadata.chain_role,
	}
}
