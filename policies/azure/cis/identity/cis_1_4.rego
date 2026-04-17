package argus.azure.cis.cis_1_4

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "cis_1_4",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Identity",
	"title": "Ensure no custom subscription owner roles are created",
	"description": "Custom roles with Owner privileges bypass standard controls and can be used to obscure privilege escalation paths.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Least privilege role assignment",
	"nist_800_53": "AC-6(1)",
	"cis_rule": "1.4",
	"mitre_technique": "T1098",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

is_custom_owner(ra) if {
	contains(lower(ra.role_name), "owner")
	object.get(ra, "role_type", "") == "CustomRole"
}

violation contains msg if {
	affected := [a | a := input.role_assignments[_]; is_custom_owner(a)]
	count(affected) > 0
	sub := object.get(input, "subscription", {})
	sub_id := object.get(sub, "id", "unknown")
	sample := [name |
		some i
		i < 25
		name := affected[i].role_name
	]
	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("%s/customOwnerRoles", [sub_id]),
		"resource_type": "Microsoft.Authorization/roleAssignments",
		"resource_name": "subscription",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%d custom role assignment(s) grant Owner-equivalent privileges. Use the built-in Owner role instead so privileges remain auditable.", [count(affected)]),
		"evidence": {
			"affected_count": count(affected),
			"subscription_id": sub_id,
			"sample_roles": sample,
		},
		"chain_role": metadata.chain_role,
	}
}
