package argus.azure.zt.zt_bak_004

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_bak_004",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Recovery Services backup policy has retention below 7 days",
	"description": "Backup policies with shorter retention than 7 days cannot recover a workload from a malicious action that went unnoticed for more than the retention window. Ransomware groups routinely stay dormant for 3-5 days before encryption to ensure backups of the clean state are gone. 7-day retention is the minimum floor; regulated workloads need 30+ days.",
	"zt_tenet": "Tenet 4",
	"nist_800_207": "Tenet 4 - Access to individual enterprise resources is granted on a per-session basis",
	"nist_800_53": "CP-9",
	"cis_rule": "",
	"mitre_technique": "T1490",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.recoveryservices/vaults/backuppolicies"
	props := object.get(resource, "properties", {})
	retention := object.get(props, "retentionPolicy", {})
	daily := object.get(retention, "dailySchedule", {})
	count_val := object.get(daily, "retentionDuration", {})
	count_days := object.get(count_val, "count", 0)
	count_days > 0
	count_days < 7

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Backup policy '%s' has daily-retention duration of %d days. Increase to at least 7 (and 30+ for regulated workloads).", [resource.name, count_days]),
		"evidence": {"dailyRetentionDays": count_days},
		"chain_role": metadata.chain_role,
	}
}
