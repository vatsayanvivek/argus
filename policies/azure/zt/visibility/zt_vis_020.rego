package argus.azure.zt.visibility.zt_vis_020

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_020",
	"source": "argus-zt",
	"severity": "LOW",
	"pillar": "Visibility",
	"title": "Defender for Cloud email notifications not configured",
	"description": "Email notifications ensure security teams receive Defender for Cloud alerts directly. Without them, critical alerts may be missed or delayed.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "IR-6",
	"cis_rule": "",
	"mitre_technique": "T1562.008",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	ts := object.get(input, "tenant_settings", {})
	object.get(ts, "defender_email_notifications", false) != true
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.Security/securityContacts",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' does not have Defender for Cloud email notifications configured. Critical security alerts may be missed.", [object.get(sub, "display_name", "subscription")]),
		"evidence": {
			"defender_email_notifications": false,
		},
		"chain_role": metadata.chain_role,
	}
}
