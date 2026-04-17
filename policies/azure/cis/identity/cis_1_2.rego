package argus.azure.cis.cis_1_2

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "cis_1_2",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Identity",
	"title": "Ensure MFA is enabled for all privileged users",
	"description": "Checks that users with privileged roles such as Global Administrator or Privileged Role Administrator have MFA enabled. Privileged accounts are high value targets.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Strict authentication for privileged resources",
	"nist_800_53": "IA-2(1)",
	"cis_rule": "1.2",
	"mitre_technique": "T1078.004",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

privileged_roles := {
	"Global Administrator",
	"Privileged Role Administrator",
	"Security Administrator",
	"User Administrator",
	"Exchange Administrator",
	"SharePoint Administrator",
	"Conditional Access Administrator",
}

is_priv_no_mfa(user) if {
	user.account_enabled == true
	role := user.assigned_roles[_]
	privileged_roles[role]
	object.get(user, "mfa_enabled", false) == false
}

violation contains msg if {
	affected := [u | u := input.users[_]; is_priv_no_mfa(u)]
	count(affected) > 0
	sub := object.get(input, "subscription", {})
	tenant_id := object.get(sub, "tenant_id", "unknown")
	sample := [upn |
		some i
		i < 25
		upn := affected[i].user_principal_name
	]
	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("tenant:%s/privileged-no-mfa", [tenant_id]),
		"resource_type": "Microsoft.AAD/tenant",
		"resource_name": "tenant",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%d privileged user(s) hold privileged roles without MFA configured. Compromise of any one yields tenant-wide control.", [count(affected)]),
		"evidence": {
			"affected_count": count(affected),
			"tenant_id": tenant_id,
			"sample_users": sample,
		},
		"chain_role": metadata.chain_role,
	}
}
