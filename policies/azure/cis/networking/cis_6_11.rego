package argus.azure.cis.cis_6_11

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_11",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Ensure management VMs do not have public IP addresses",
	"description": "Management-tier virtual machines (jumphosts, bastions named 'mgmt') should be reachable only via Azure Bastion or private networking, never via direct public IP.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication regardless of network",
	"nist_800_53": "SC-7",
	"cis_rule": "6.11",
	"mitre_technique": "T1021",
	"mitre_tactic": "Lateral Movement",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

is_mgmt(vm) if {
	contains(lower(vm.name), "mgmt")
}

is_mgmt(vm) if {
	tags := object.get(vm, "tags", {})
	role := object.get(tags, "role", "")
	contains(lower(role), "mgmt")
}

has_public_ip(vm) if {
	nic := vm.properties.networkProfile.networkInterfaces[_]
	pip := input.public_ips[_]
	nic_id := object.get(pip, "attached_nic_id", "")
	nic_id == nic.id
}

violation contains msg if {
	vm := input.virtual_machines[_]
	is_mgmt(vm)
	has_public_ip(vm)
	msg := {
		"rule_id": metadata.id,
		"resource_id": vm.id,
		"resource_type": vm.type,
		"resource_name": vm.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Management VM '%v' has a public IP address. Management tier should be reachable only via Bastion or private peering.", [vm.name]),
		"evidence": {
			"vm_id": vm.id,
			"vm_name": vm.name,
		},
		"chain_role": metadata.chain_role,
	}
}
