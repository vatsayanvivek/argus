package argus.azure.zt.zt_data_021

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_021",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Azure Data Factory is internet-accessible for integration runtime control plane",
	"description": "Data Factory orchestrates data movement across storage accounts, databases, and external sources. An ADF with publicNetworkAccess=Enabled exposes the integration-runtime control plane to the public internet — attackers who authenticate (e.g. via leaked SAS or compromised identity) can trigger pipelines that read from and write to every linked data source. Disable public access and use a Self-Hosted IR inside the VNet.",
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
	lower(resource.type) == "microsoft.datafactory/factories"
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
		"detail": sprintf("Data Factory '%s' has publicNetworkAccess=Enabled. Set it to Disabled and move integration runtime traffic through private endpoints or a Self-Hosted IR.", [resource.name]),
		"evidence": {"publicNetworkAccess": public},
		"chain_role": metadata.chain_role,
	}
}
