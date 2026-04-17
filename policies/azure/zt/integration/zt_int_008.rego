package argus.azure.zt.zt_int_008

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_008",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "API Management is not deployed in internal-VNet mode for sensitive backends",
	"description": "APIM instances in External VNet mode terminate the public-gateway at the Azure edge, then reach private backends. Internal VNet mode puts the whole gateway inside the customer VNet — the public endpoint is absent, callers must come via Application Gateway / Front Door. For APIM fronting regulated workloads, Internal VNet is the defense-in-depth posture.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "SC-7",
	"cis_rule": "",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.apimanagement/service"
	props := object.get(resource, "properties", {})
	vnet_type := object.get(props, "virtualNetworkType", "None")
	vnet_type != "Internal"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("APIM service '%s' has virtualNetworkType=%s (not Internal). For sensitive APIs, deploy APIM in Internal VNet mode behind Application Gateway / Front Door.", [resource.name, vnet_type]),
		"evidence": {"virtualNetworkType": vnet_type},
		"chain_role": metadata.chain_role,
	}
}
