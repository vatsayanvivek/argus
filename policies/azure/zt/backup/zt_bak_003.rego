package argus.azure.zt.zt_bak_003

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_bak_003",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Recovery Services Vault has no cross-region restore",
	"description": "Cross-Region Restore (CRR) replicates recovery points to the paired Azure region automatically. Without it, a region-wide outage or accidental vault deletion leaves the workload with no restore target. CRR is free for GRS-storage vaults and must be explicitly enabled — it is not the default.",
	"zt_tenet": "Tenet 4",
	"nist_800_207": "Tenet 4 - Access to individual enterprise resources is granted on a per-session basis",
	"nist_800_53": "CP-9, CP-10",
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
	storage_config := object.get(props, "storageConfig", {})
	crr := object.get(storage_config, "crossRegionRestoreFlag", false)
	crr == false

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Recovery Services Vault '%s' does not have cross-region restore enabled. A region outage leaves this vault's recovery points unreachable.", [resource.name]),
		"evidence": {"crossRegionRestoreFlag": crr},
		"chain_role": metadata.chain_role,
	}
}
