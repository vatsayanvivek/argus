package argus.azure.zt.zt_data_022

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_022",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Databricks workspace deploys worker VMs with public IPs",
	"description": "Databricks workspaces created without 'noPublicIp'=true provision each driver and worker with a public IP address. Worker nodes then initiate outbound connections to the Databricks control plane from a public endpoint, and any misconfigured NSG/firewall leaves them reachable from the internet. Secure cluster connectivity (noPublicIp=true) keeps workers on private IPs only.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "SC-7",
	"cis_rule": "",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.databricks/workspaces"
	props := object.get(resource, "properties", {})
	params := object.get(props, "parameters", {})
	no_public_ip := object.get(params, "enableNoPublicIp", {})
	no_public_ip_value := object.get(no_public_ip, "value", false)
	no_public_ip_value == false

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Databricks workspace '%s' has noPublicIp=false — driver and worker VMs receive public IP addresses. Recreate the workspace with 'Secure cluster connectivity' enabled, or deploy via VNet injection with noPublicIp=true.", [resource.name]),
		"evidence": {"enableNoPublicIp": no_public_ip_value},
		"chain_role": metadata.chain_role,
	}
}
