package argus.azure.zt.zt_bak_002

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_bak_002",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Recovery Services Vault has soft delete disabled",
	"description": "Without soft delete, a Backup operator (or attacker who compromised one) can permanently delete recovery points in a single API call. Soft delete gives 14 days to recover from accidental or malicious deletion. It is free, has no performance cost, and the default should never be disabled except for development vaults.",
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
	lower(resource.type) == "microsoft.recoveryservices/vaults"
	props := object.get(resource, "properties", {})
	sec := object.get(props, "securitySettings", {})
	soft_delete := object.get(sec, "softDeleteSettings", {})
	state := object.get(soft_delete, "softDeleteState", "Enabled")
	state != "AlwaysON"
	state != "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Recovery Services Vault '%s' has softDeleteState=%s. Enable it (ideally AlwaysON for production vaults).", [resource.name, state]),
		"evidence": {"softDeleteState": state},
		"chain_role": metadata.chain_role,
	}
}
