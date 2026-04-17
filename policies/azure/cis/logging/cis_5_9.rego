package argus.azure.cis.cis_5_9

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_9",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Network Security Group flow log retention set to >= 90 days",
	"description": "NSG flow log retention below 90 days limits forensic investigation of network-based attacks including lateral movement and data exfiltration.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "AU-11",
	"cis_rule": "5.9",
	"mitre_technique": "T1070",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
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
		"detail": sprintf("NSG flow log '%v' retention is %d days, below the 90-day minimum for adequate forensic investigation.", [object.get(r, "name", ""), days]),
		"evidence": {
			"resource_id": object.get(r, "id", ""),
			"retention_days": days,
			"minimum_required": 90,
		},
		"chain_role": metadata.chain_role,
	}
}
