package argus.azure.cis.cis_1_1

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "cis_1_1",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Identity",
	"title": "Ensure Multi-Factor Authentication is enabled for all non-privileged users",
	"description": "Checks that all enabled member users in Azure AD have MFA enabled. MFA significantly reduces the risk of credential compromise and unauthorized access.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-2(1)",
	"cis_rule": "1.1",
	"mitre_technique": "T1078",
	"mitre_tactic": "Initial Access",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

# Aggregating rule: emit ONE finding per tenant summarising all
# enabled member users that lack MFA. The full list is recorded in
# evidence so reports can drill in without flooding the output.
violation contains msg if {
	affected := [u |
		u := input.users[_]
		u.account_enabled == true
		u.user_type == "Member"
		object.get(u, "mfa_enabled", false) == false
	]
	count(affected) > 0
	sub := object.get(input, "subscription", {})
	tenant_id := object.get(sub, "tenant_id", "unknown")

	# Build a sample list (first 25 affected UPNs) so the evidence
	# block stays bounded and human-readable.
	sample_upns := [upn |
		some i
		i < 25
		upn := affected[i].user_principal_name
	]

	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("tenant:%s", [tenant_id]),
		"resource_type": "Microsoft.AAD/tenant",
		"resource_name": "tenant",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%d enabled member user(s) in this tenant have no MFA configured. Attackers can compromise these accounts via phishing or password spraying.", [count(affected)]),
		"evidence": {
			"affected_count": count(affected),
			"tenant_id": tenant_id,
			"sample_users": sample_upns,
		},
		"chain_role": metadata.chain_role,
	}
}
