package argus.azure.zt.visibility.zt_vis_011

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_011",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "No Log Analytics workspace configured in subscription",
	"description": "A Log Analytics workspace is the central aggregation point for Azure Monitor, Defender, and Sentinel. Without one, no centralized logging or detection is possible.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-6",
	"cis_rule": "",
	"mitre_technique": "T1562.008",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

has_log_analytics_workspace if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.operationalinsights/workspaces"
}

violation contains msg if {
	not has_log_analytics_workspace
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.OperationalInsights/workspaces",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no Log Analytics workspace. Centralized logging and detection are not possible.", [object.get(sub, "display_name", "subscription")]),
		"evidence": {
			"log_analytics_workspace_count": 0,
		},
		"chain_role": metadata.chain_role,
	}
}
