package argus.azure.cis.cis_1_9

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_9",
	"source": "argus-cis",
	"severity": "LOW",
	"pillar": "Identity",
	"title": "Ensure admins are notified on password resets",
	"description": "Admins should be notified whenever self-service password resets occur on privileged accounts to detect unauthorized resets quickly.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect information about asset security posture",
	"nist_800_53": "AU-2",
	"cis_rule": "1.9",
	"mitre_technique": "T1098",
	"mitre_tactic": "Persistence",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	notif := object.get(input.tenant_settings, "password_reset_notification", false)
	notif == false
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.AAD/tenantSettings",
		"resource_name": "password_reset_notification",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": "Password reset notifications are disabled. Admins will not learn of SSPR events that could indicate credential theft.",
		"evidence": {
			"password_reset_notification": notif,
		},
		"chain_role": metadata.chain_role,
	}
}
