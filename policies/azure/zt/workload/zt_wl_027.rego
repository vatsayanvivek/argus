package argus.azure.zt.zt_wl_027

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_wl_027",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Virtual Machine Scale Set does not use managed identity",
	"description": "VMSS instances without a managed identity must authenticate to other Azure services using either (a) embedded secrets in VM extensions, or (b) a static service principal whose credentials need rotating. Managed identity removes both problems: the instance metadata service delivers a fresh token per instance per session. Every VMSS that calls Azure APIs should have SystemAssigned identity.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-5(1), IA-3",
	"cis_rule": "",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.compute/virtualmachinescalesets"
	identity := object.get(resource, "identity", {})
	identity_type := object.get(identity, "type", "None")
	identity_type == "None"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("VMSS '%s' has no managed identity. Enable SystemAssigned or UserAssigned identity and remove static credentials from VM extensions.", [resource.name]),
		"evidence": {"identityType": identity_type},
		"chain_role": metadata.chain_role,
	}
}
