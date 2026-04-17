package argus.azure.zt.zt_data_023

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_023",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Synapse workspace allows public SQL endpoint access",
	"description": "Synapse workspaces with public network access enabled expose the serverless + dedicated SQL endpoints to the internet. SQL Auth or Entra ID tokens then become the only barrier. Disable public network access and restrict access to the workspace managed VNet plus explicit private endpoints.",
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
	lower(resource.type) == "microsoft.synapse/workspaces"
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
		"detail": sprintf("Synapse workspace '%s' has publicNetworkAccess=Enabled. Disable it and route consumers through private endpoints.", [resource.name]),
		"evidence": {"publicNetworkAccess": public},
		"chain_role": metadata.chain_role,
	}
}
