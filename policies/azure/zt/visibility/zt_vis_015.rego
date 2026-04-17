package argus.azure.zt.visibility.zt_vis_015

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_015",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "SQL Server audit log retention less than 90 days",
	"description": "SQL Server auditing captures database-level events. Retention below 90 days limits the ability to investigate data tampering and unauthorized access after a breach.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-11",
	"cis_rule": "",
	"mitre_technique": "T1565",
	"mitre_tactic": "Impact",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	srv := input.sql_servers[_]
	policy := object.get(object.get(srv, "properties", {}), "auditingPolicy", {})
	days := object.get(policy, "retentionDays", 0)
	days < 90
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(srv, "id", ""),
		"resource_type": "Microsoft.Sql/servers",
		"resource_name": object.get(srv, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("SQL Server '%v' audit log retention is %d days, below the 90-day minimum for adequate forensic investigation.", [object.get(srv, "name", ""), days]),
		"evidence": {
			"server_id": object.get(srv, "id", ""),
			"retention_days": days,
			"minimum_required": 90,
		},
		"chain_role": metadata.chain_role,
	}
}
