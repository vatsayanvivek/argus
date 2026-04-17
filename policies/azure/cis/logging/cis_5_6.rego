package argus.azure.cis.cis_5_6

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_6",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure activity log alert exists for Security Solution changes",
	"description": "An alert should fire when Microsoft.Security/securitySolutions resources are created or deleted so that tampering with security posture is detected.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-6",
	"cis_rule": "5.6",
	"mitre_technique": "T1562.001",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

has_alert if {
	evt := input.activity_log[_]
	op := object.get(evt, "operation_name", "")
	contains(lower(op), "microsoft.security/securitysolutions")
	object.get(evt, "is_alert_rule", false) == true
}

violation contains msg if {
	not has_alert
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Insights/activityLogAlerts",
		"resource_name": "security_solution_alert",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("No activity log alert for Security Solution changes in subscription '%v'. Disabling security tooling will go unnoticed.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"operation": "Microsoft.Security/securitySolutions/write",
		},
		"chain_role": metadata.chain_role,
	}
}
