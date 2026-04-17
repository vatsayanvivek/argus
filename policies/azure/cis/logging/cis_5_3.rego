package argus.azure.cis.cis_5_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_3",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure activity log alert exists for Create Policy Assignment",
	"description": "An alert should fire when Microsoft.Authorization/policyAssignments/write events occur so that changes to policy posture are detected.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-6",
	"cis_rule": "5.3",
	"mitre_technique": "T1562.001",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

has_alert if {
	evt := input.activity_log[_]
	op := object.get(evt, "operation_name", "")
	contains(lower(op), "microsoft.authorization/policyassignments")
	object.get(evt, "is_alert_rule", false) == true
}

violation contains msg if {
	not has_alert
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Insights/activityLogAlerts",
		"resource_name": "policy_assignment_alert",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("No activity log alert for policyAssignments/write in subscription '%v'. Policy changes can be made silently.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"operation": "Microsoft.Authorization/policyAssignments/write",
		},
		"chain_role": metadata.chain_role,
	}
}
