package argus.azure.cis.cis_7_1

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_7_1",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Ensure endpoint protection is installed on VMs",
	"description": "VMs should have an antimalware extension installed (Microsoft Antimalware, Defender for Endpoint, etc.) to detect and prevent malicious code execution.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Monitor and measure integrity and security posture",
	"nist_800_53": "SI-3",
	"cis_rule": "7.1",
	"mitre_technique": "T1059",
	"mitre_tactic": "Execution",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

antimalware_keywords := {"antimalware", "defender", "endpoint", "mdatp"}

has_antimalware(vm) if {
	ext := vm.properties.extensions[_]
	name := lower(object.get(ext, "name", ""))
	kw := antimalware_keywords[_]
	contains(name, kw)
}

has_antimalware(vm) if {
	ext := vm.properties.extensions[_]
	pub := lower(object.get(ext, "publisher", ""))
	kw := antimalware_keywords[_]
	contains(pub, kw)
}

violation contains msg if {
	vm := input.virtual_machines[_]
	not has_antimalware(vm)
	msg := {
		"rule_id": metadata.id,
		"resource_id": vm.id,
		"resource_type": vm.type,
		"resource_name": vm.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VM '%v' has no endpoint protection extension installed. Malicious code will execute without interference.", [vm.name]),
		"evidence": {
			"vm_id": vm.id,
			"extensions_count": count(object.get(vm.properties, "extensions", [])),
		},
		"chain_role": metadata.chain_role,
	}
}
