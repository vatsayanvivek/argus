package argus.azure.zt.zt_ai_004

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "zt_ai_004",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Azure ML Workspace is internet-exposed",
	"description": "An Azure Machine Learning workspace with public network access hosts training compute, model registries, and datasets reachable from the internet. Adversaries can enumerate model endpoints, attempt to pull training data via misconfigured registries, or issue control-plane calls that manipulate training jobs. ML workspaces should live behind a managed virtual network or private endpoint.",
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
	lower(resource.type) == "microsoft.machinelearningservices/workspaces"
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
		"detail": sprintf("Azure ML workspace '%s' has public network access enabled. Configure managed VNet isolation (v1/v2) or deny public inbound via private endpoint.", [resource.name]),
		"evidence": {"publicNetworkAccess": public},
		"chain_role": metadata.chain_role,
	}
}
