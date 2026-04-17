package argus.azure.zt.zt_vis_021

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "zt_vis_021",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "No Activity Log alert for role assignment creation at subscription scope",
	"description": "Without an Activity Log alert on 'Microsoft.Authorization/roleAssignments/write', nobody gets paged when an attacker with Owner or UAA grants themselves (or a backdoor SP) a new role. This is the single highest-value alert in any Azure environment — a true positive always means privilege movement is happening. If it isn't wired up, RBAC drift goes unnoticed until the next audit.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - The enterprise collects as much information as possible about the current state of assets",
	"nist_800_53": "AU-6, SI-4",
	"cis_rule": "",
	"mitre_technique": "T1098.003",
	"mitre_tactic": "Persistence",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	# Look across all activity log alerts in the snapshot for one
	# matching 'Microsoft.Authorization/roleAssignments/write'.
	not role_assignment_alert_exists

	sub := object.get(input, "subscription", {})
	sub_id := object.get(sub, "id", "unknown")

	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("subscription:%s", [sub_id]),
		"resource_type": "Microsoft.Insights/activityLogAlerts",
		"resource_name": "missing role-assignment alert",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": "No Activity Log alert exists for the 'Microsoft.Authorization/roleAssignments/write' operation. Create one targeting the subscription with an action group that pages a human.",
		"evidence": {"subscription_id": sub_id},
		"chain_role": metadata.chain_role,
	}
}

role_assignment_alert_exists if {
	alert := input.resources[_]
	lower(alert.type) == "microsoft.insights/activitylogalerts"
	props := object.get(alert, "properties", {})
	object.get(props, "enabled", false) == true
	conditions := object.get(object.get(props, "condition", {}), "allOf", [])
	some c in conditions
	lower(object.get(c, "field", "")) == "operationname"
	lower(object.get(c, "equals", "")) == "microsoft.authorization/roleassignments/write"
}
