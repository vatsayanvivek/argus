package argus.azure.cis.cis_1_12

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "cis_1_12",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Identity",
	"title": "Ensure guest users do not have privileged role assignments",
	"description": "B2B guest users holding privileged roles create cross-tenant trust that is difficult to audit and control. Privileged guests are a top persistence vector.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Least privilege, dynamic authorization",
	"nist_800_53": "AC-6",
	"cis_rule": "1.12",
	"mitre_technique": "T1078.004",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

privileged_roles := {
	"Owner",
	"Contributor",
	"User Access Administrator",
	"Global Administrator",
	"Privileged Role Administrator",
	"Security Administrator",
}

user_by_id[pid] := u if {
	u := input.users[_]
	pid := u.id
}

is_guest_with_priv(ra) if {
	privileged_roles[ra.role_name]
	ra.principal_type == "User"
	u := user_by_id[ra.principal_id]
	u.user_type == "Guest"
}

violation contains msg if {
	affected := [a | a := input.role_assignments[_]; is_guest_with_priv(a)]
	count(affected) > 0
	sub := object.get(input, "subscription", {})
	sub_id := object.get(sub, "id", "unknown")
	sample := [item |
		some i
		i < 25
		ra := affected[i]
		u := user_by_id[ra.principal_id]
		item := sprintf("%s (%s)", [u.user_principal_name, ra.role_name])
	]
	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("%s/guestPrivilegedAssignments", [sub_id]),
		"resource_type": "Microsoft.Authorization/roleAssignments",
		"resource_name": "subscription",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%d guest user(s) hold privileged role assignments. Cross-tenant privileged access creates an extremely risky persistence vector.", [count(affected)]),
		"evidence": {
			"affected_count": count(affected),
			"subscription_id": sub_id,
			"sample_assignments": sample,
		},
		"chain_role": metadata.chain_role,
	}
}
