package argus.azure.cis.cis_5_5

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_5",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure activity log alert exists for SQL firewall rule changes",
	"description": "An alert should fire when SQL server firewall rules are created or modified so that database perimeter changes are detected.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-6",
	"cis_rule": "5.5",
	"mitre_technique": "T1562.007",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

has_alert if {
	evt := input.activity_log[_]
	op := object.get(evt, "operation_name", "")
	contains(lower(op), "microsoft.sql/servers/firewallrules")
	object.get(evt, "is_alert_rule", false) == true
}

violation contains msg if {
	not has_alert
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Insights/activityLogAlerts",
		"resource_name": "sql_firewall_alert",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("No activity log alert for SQL firewall rule changes in subscription '%v'.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"operation": "Microsoft.Sql/servers/firewallRules/write",
		},
		"chain_role": metadata.chain_role,
	}
}
