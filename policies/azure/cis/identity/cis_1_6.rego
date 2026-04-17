package argus.azure.cis.cis_1_6

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_6",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "Ensure that 'Guest invite restrictions' is set to admins only",
	"description": "External invitations should be restricted so that not every member user can invite guests. Unrestricted invites enable easy persistence and unwanted data sharing.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - All communication secured regardless of network",
	"nist_800_53": "AC-3",
	"cis_rule": "1.6",
	"mitre_technique": "T1136.003",
	"mitre_tactic": "Persistence",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	setting := object.get(input.tenant_settings, "guest_invite_restrictions", "everyone")
	setting == "everyone"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.AAD/tenantSettings",
		"resource_name": "guest_invite_restrictions",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Tenant allows '%v' to invite external users. Any member can bring in guest users, undermining the identity perimeter.", [setting]),
		"evidence": {
			"guest_invite_restrictions": setting,
		},
		"chain_role": metadata.chain_role,
	}
}
