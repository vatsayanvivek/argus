package argus.azure.zt.visibility.zt_vis_018

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_018",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "No Azure Monitor action groups configured",
	"description": "Action groups define notification recipients and automation targets for alert rules. Without at least one action group, alerts cannot reach operators or trigger automated response.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "IR-6",
	"cis_rule": "",
	"mitre_technique": "T1562",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

has_action_group if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.insights/actiongroups"
}

violation contains msg if {
	not has_action_group
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.Insights/actionGroups",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no Azure Monitor action groups. Alert notifications cannot be delivered to operators.", [object.get(sub, "display_name", "subscription")]),
		"evidence": {
			"action_group_count": 0,
		},
		"chain_role": metadata.chain_role,
	}
}
