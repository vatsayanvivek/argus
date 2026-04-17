package argus.azure.zt.zt_bak_005

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_bak_005",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Site Recovery replication policy uses inadequate RPO",
	"description": "Azure Site Recovery replication policies with an RPO (recovery point objective) of 30 minutes or worse leave too much time between replication snapshots — a ransomware or data-corruption event discovered 20 minutes after impact may not have a clean recovery point within the RPO window. For production workloads, RPO <= 15 minutes is the baseline; mission-critical should target 5 minutes.",
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
	lower(resource.type) == "microsoft.recoveryservices/vaults/replicationpolicies"
	props := object.get(resource, "properties", {})
	provider := object.get(props, "providerSpecificDetails", {})
	rpo_minutes := object.get(provider, "recoveryPointThresholdInMinutes", 60)
	rpo_minutes > 30

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Site Recovery replication policy '%s' has RPO=%d minutes. Lower to <=15 (or <=5 for mission-critical).", [resource.name, rpo_minutes]),
		"evidence": {"recoveryPointThresholdInMinutes": rpo_minutes},
		"chain_role": metadata.chain_role,
	}
}
