package argus.azure.cis.cis_7_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_7_4",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure vulnerability assessment is enabled on VMs",
	"description": "VMs should have a vulnerability assessment solution installed (Qualys, Defender for Endpoint vuln mgmt, etc.) to continuously enumerate CVE exposure.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "RA-5",
	"cis_rule": "7.4",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

va_keywords := {"qualys", "vuln", "scanner", "mdevulnassessment", "defender"}

has_va(vm) if {
	ext := vm.properties.extensions[_]
	name := lower(object.get(ext, "name", ""))
	kw := va_keywords[_]
	contains(name, kw)
}

violation contains msg if {
	vm := input.virtual_machines[_]
	not has_va(vm)
	msg := {
		"rule_id": metadata.id,
		"resource_id": vm.id,
		"resource_type": vm.type,
		"resource_name": vm.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VM '%v' has no vulnerability assessment extension. CVE exposure cannot be measured.", [vm.name]),
		"evidence": {
			"vm_id": vm.id,
			"extensions_count": count(object.get(vm.properties, "extensions", [])),
		},
		"chain_role": metadata.chain_role,
	}
}
