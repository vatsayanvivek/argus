package argus.azure.cis.cis_5_8

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_8",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Activity Log retention set to 365 days or more",
	"description": "Activity Log retention below 365 days limits the ability to investigate historical control-plane operations during long-dwell-time breaches.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "AU-11",
	"cis_rule": "5.8",
	"mitre_technique": "T1070",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	ts := object.get(input, "tenant_settings", {})
	days := object.get(ts, "activity_log_retention_days", 0)
	days < 365
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.Insights/diagnosticSettings",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' activity log retention is %d days, below the 365-day minimum. Historical control-plane events may be lost.", [object.get(sub, "display_name", "subscription"), days]),
		"evidence": {
			"retention_days": days,
			"minimum_required": 365,
		},
		"chain_role": metadata.chain_role,
	}
}
