package argus.azure.zt.zt_data_027

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_027",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Microsoft Purview account allows public network access",
	"description": "Purview is a data-catalog service that indexes metadata across your Azure data estate — including schema, lineage, and classification tags for sensitive data. Leaving publicNetworkAccess=Enabled exposes this catalog to the internet, giving adversaries a free reconnaissance API for 'where is the interesting data in this tenant'. Catalogues belong on private endpoints.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "AC-4, SC-7",
	"cis_rule": "",
	"mitre_technique": "T1190",
	"mitre_tactic": "Reconnaissance",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.purview/accounts"
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
		"detail": sprintf("Purview account '%s' has publicNetworkAccess=Enabled. Disable it and route consumers through private endpoints.", [resource.name]),
		"evidence": {"publicNetworkAccess": public},
		"chain_role": metadata.chain_role,
	}
}
