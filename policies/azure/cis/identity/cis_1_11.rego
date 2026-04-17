package argus.azure.cis.cis_1_11

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "cis_1_11",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Identity",
	"title": "Ensure disabled user accounts do not hold role assignments",
	"description": "Role assignments tied to disabled accounts represent dormant privilege that can be reactivated silently if the account is re-enabled.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Dynamic authorization",
	"nist_800_53": "AC-2(3)",
	"cis_rule": "1.11",
	"mitre_technique": "T1098",
	"mitre_tactic": "Persistence",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

user_by_id[pid] := u if {
	u := input.users[_]
	pid := u.id
}

is_disabled_with_role(ra) if {
	ra.principal_type == "User"
	u := user_by_id[ra.principal_id]
	u.account_enabled == false
}

violation contains msg if {
	affected := [a | a := input.role_assignments[_]; is_disabled_with_role(a)]
	count(affected) > 0
	sub := object.get(input, "subscription", {})
	sub_id := object.get(sub, "id", "unknown")
	sample := [name |
		some i
		i < 25
		ra := affected[i]
		u := user_by_id[ra.principal_id]
		name := sprintf("%s (%s)", [u.user_principal_name, ra.role_name])
	]
	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("%s/disabledUsersWithRoles", [sub_id]),
		"resource_type": "Microsoft.Authorization/roleAssignments",
		"resource_name": "subscription",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%d disabled user account(s) still hold role assignments. Reactivating any of these silently restores their privileges.", [count(affected)]),
		"evidence": {
			"affected_count": count(affected),
			"subscription_id": sub_id,
			"sample_assignments": sample,
		},
		"chain_role": metadata.chain_role,
	}
}
