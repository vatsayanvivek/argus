package argus.azure.cis.cis_5_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_4",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure activity log alert exists for NSG rule changes",
	"description": "An alert should fire when network security group rules are created, updated, or deleted so that perimeter changes are detected.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-6",
	"cis_rule": "5.4",
	"mitre_technique": "T1562.007",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

has_alert if {
	evt := input.activity_log[_]
	op := object.get(evt, "operation_name", "")
	contains(lower(op), "microsoft.network/networksecuritygroups")
	object.get(evt, "is_alert_rule", false) == true
}

violation contains msg if {
	not has_alert
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Insights/activityLogAlerts",
		"resource_name": "nsg_change_alert",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("No activity log alert for NSG rule changes in subscription '%v'. Firewall modifications can go unnoticed.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"operation": "Microsoft.Network/networkSecurityGroups/securityRules/write",
		},
		"chain_role": metadata.chain_role,
	}
}
