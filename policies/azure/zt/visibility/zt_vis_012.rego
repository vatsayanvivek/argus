package argus.azure.zt.visibility.zt_vis_012

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_012",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "No Azure Monitor alert rules configured for critical operations",
	"description": "Alert rules trigger notifications when critical operations occur. Without metric or activity log alerts, anomalous behaviour will not be detected in real time.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-6",
	"cis_rule": "",
	"mitre_technique": "T1562",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

has_alert_rule if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.insights/metricalerts"
}

has_alert_rule if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.insights/activitylogalerts"
}

violation contains msg if {
	not has_alert_rule
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.Insights/metricAlerts",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no Azure Monitor alert rules (metric or activity log). Critical operations will not trigger notifications.", [object.get(sub, "display_name", "subscription")]),
		"evidence": {
			"metric_alert_count": 0,
			"activity_log_alert_count": 0,
		},
		"chain_role": metadata.chain_role,
	}
}
