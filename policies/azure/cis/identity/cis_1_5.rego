package argus.azure.cis.cis_1_5

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "cis_1_5",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Identity",
	"title": "Ensure all subscription Owners have MFA enabled",
	"description": "Checks that users assigned the Owner role on the subscription have MFA. Subscription Owners can modify any resource in the subscription.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Strict authentication for privileged resources",
	"nist_800_53": "IA-2(1)",
	"cis_rule": "1.5",
	"mitre_technique": "T1078.004",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

user_by_id[pid] := u if {
	u := input.users[_]
	pid := u.id
}

is_owner_no_mfa(ra) if {
	ra.role_name == "Owner"
	ra.principal_type == "User"
	u := user_by_id[ra.principal_id]
	object.get(u, "mfa_enabled", false) == false
}

violation contains msg if {
	affected := [a | a := input.role_assignments[_]; is_owner_no_mfa(a)]
	count(affected) > 0
	sub := object.get(input, "subscription", {})
	sub_id := object.get(sub, "id", "unknown")
	sample := [upn |
		some i
		i < 25
		ra := affected[i]
		u := user_by_id[ra.principal_id]
		upn := u.user_principal_name
	]
	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("%s/ownersWithoutMFA", [sub_id]),
		"resource_type": "Microsoft.Authorization/roleAssignments",
		"resource_name": "subscription",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%d subscription Owner(s) do not have MFA enabled. Owner compromise yields full subscription control.", [count(affected)]),
		"evidence": {
			"affected_count": count(affected),
			"subscription_id": sub_id,
			"sample_users": sample,
		},
		"chain_role": metadata.chain_role,
	}
}
