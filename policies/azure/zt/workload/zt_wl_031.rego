package argus.azure.zt.zt_wl_031

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_wl_031",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Batch account accepts public-endpoint pool access (no private endpoint)",
	"description": "Azure Batch accounts with publicNetworkAccess='Enabled' expose the pool-management and task-submission endpoints to the internet. Any user with a valid Batch account key or Entra token can queue compute work — including from compromised laptops. Put Batch accounts on private endpoints; the performance cost is zero and the attack surface drops to zero.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "AC-4, SC-7",
	"cis_rule": "",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.batch/batchaccounts"
	props := object.get(resource, "properties", {})
	public := object.get(props, "publicNetworkAccess", "Enabled")
	public == "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Batch account '%s' has publicNetworkAccess=Enabled. Disable it and route access via private endpoint.", [resource.name]),
		"evidence": {"publicNetworkAccess": public},
		"chain_role": metadata.chain_role,
	}
}
