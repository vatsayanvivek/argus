package argus.azure.cis.cis_1_24

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_24",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "Custom subscription owner roles are not created",
	"description": "Custom roles with Owner-equivalent permissions bypass the governance controls applied to built-in Owner. Custom owner roles should not be created; use built-in Owner with PIM instead.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "AC-6",
	"cis_rule": "1.24",
	"mitre_technique": "T1078",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

is_custom_owner(role) if {
	object.get(role, "roleType", "") == "CustomRole"
	perms := object.get(role, "permissions", [])
	perm := perms[_]
	actions := object.get(perm, "actions", [])
	action := actions[_]
	action == "*"
}

violation contains msg if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.authorization/roledefinitions"
	is_custom_owner(object.get(r, "properties", {}))
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(r, "id", ""),
		"resource_type": "Microsoft.Authorization/roleDefinitions",
		"resource_name": object.get(r, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Custom role '%v' has Owner-equivalent permissions (actions: '*'). Use built-in Owner with PIM instead of custom owner roles.", [object.get(object.get(r, "properties", {}), "roleName", object.get(r, "name", ""))]),
		"evidence": {
			"role_id": object.get(r, "id", ""),
			"role_name": object.get(object.get(r, "properties", {}), "roleName", ""),
			"role_type": "CustomRole",
		},
		"chain_role": metadata.chain_role,
	}
}
