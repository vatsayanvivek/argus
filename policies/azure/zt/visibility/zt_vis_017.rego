package argus.azure.zt.visibility.zt_vis_017

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_017",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Activity log not exported to Log Analytics workspace",
	"description": "The Azure Activity Log records all control-plane operations. Without export to a Log Analytics workspace, Sentinel and Defender cannot correlate ARM-layer events with resource-level telemetry.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-6",
	"cis_rule": "",
	"mitre_technique": "T1562.008",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	ts := object.get(input, "tenant_settings", {})
	object.get(ts, "activity_log_export", false) != true
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.Insights/diagnosticSettings",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' activity log is not exported to a Log Analytics workspace. Control-plane events are not available for correlation.", [object.get(sub, "display_name", "subscription")]),
		"evidence": {
			"activity_log_export": false,
		},
		"chain_role": metadata.chain_role,
	}
}
