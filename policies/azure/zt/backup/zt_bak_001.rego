package argus.azure.zt.zt_bak_001

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_bak_001",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Recovery Services Vault lacks immutability protection",
	"description": "Recovery Services Vaults without immutability enabled allow operators with Backup Contributor (or higher) privilege to delete or mutate recovery points. In a ransomware scenario the attacker's first move after privilege escalation is to destroy backups so the victim has no choice but to pay. Immutable vaults refuse recovery-point deletion for the retention period, eliminating this attack step.",
	"zt_tenet": "Tenet 4",
	"nist_800_207": "Tenet 4 - Access to individual enterprise resources is granted on a per-session basis",
	"nist_800_53": "CP-9, SI-7",
	"cis_rule": "",
	"mitre_technique": "T1490",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.recoveryservices/vaults"
	props := object.get(resource, "properties", {})
	immutability := object.get(props, "immutabilitySettings", {})
	state := object.get(immutability, "state", "Disabled")
	state != "Locked"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Recovery Services Vault '%s' immutability is %s (not Locked). Ransomware-ready vaults require immutability=Locked so recovery points can't be deleted before their retention expires.", [resource.name, state]),
		"evidence": {"immutabilityState": state},
		"chain_role": metadata.chain_role,
	}
}
