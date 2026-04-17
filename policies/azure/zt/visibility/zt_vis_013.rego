package argus.azure.zt.visibility.zt_vis_013

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_013",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "NSG flow log retention period is less than 90 days",
	"description": "NSG flow logs record network traffic metadata. Retention below 90 days limits the ability to investigate lateral movement and data exfiltration after a breach.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-11",
	"cis_rule": "",
	"mitre_technique": "T1070",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	r := input.resources[_]
	lower(object.get(r, "type", "")) == "microsoft.network/networkwatchers/flowlogs"
	retention := object.get(object.get(r, "properties", {}), "retentionPolicy", {})
	days := object.get(retention, "days", 0)
	days < 90
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(r, "id", ""),
		"resource_type": "Microsoft.Network/networkWatchers/flowLogs",
		"resource_name": object.get(r, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("NSG flow log '%v' retention is %d days, which is below the 90-day minimum for adequate forensic investigation.", [object.get(r, "name", ""), days]),
		"evidence": {
			"resource_id": object.get(r, "id", ""),
			"retention_days": days,
			"minimum_required": 90,
		},
		"chain_role": metadata.chain_role,
	}
}
