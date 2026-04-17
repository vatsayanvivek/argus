package argus.azure.zt.zt_wl_029

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_wl_029",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Workload",
	"title": "VMSS has no automatic OS-image upgrade policy",
	"description": "VMSS instances without automaticOSUpgradePolicy.enableAutomaticOSUpgrade=true lag behind the latest image publisher's security patches. Every unpatched CVE in the base image becomes a persistent foothold across every instance the scale set spawns. Enable automatic upgrades with health-probe gating to balance availability and patch cadence.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "SI-2",
	"cis_rule": "",
	"mitre_technique": "T1068",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.compute/virtualmachinescalesets"
	props := object.get(resource, "properties", {})
	upgrade_policy := object.get(props, "upgradePolicy", {})
	auto_os := object.get(upgrade_policy, "automaticOSUpgradePolicy", {})
	enabled := object.get(auto_os, "enableAutomaticOSUpgrade", false)
	enabled == false

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VMSS '%s' has enableAutomaticOSUpgrade=%v. Enable automatic OS upgrades to keep instances current with publisher patches.", [resource.name, enabled]),
		"evidence": {"enableAutomaticOSUpgrade": enabled},
		"chain_role": metadata.chain_role,
	}
}
