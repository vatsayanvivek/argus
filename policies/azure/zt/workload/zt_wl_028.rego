package argus.azure.zt.zt_wl_028

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_wl_028",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Service Fabric cluster uses certificate thumbprint auth instead of Entra ID",
	"description": "Service Fabric clusters with certificateThumbprint-based admin authentication rely on a long-lived certificate in the cluster's configuration. Rotation is painful, private-key extraction from any cluster node gives full admin. Modern Service Fabric supports 'azureActiveDirectory' authentication with group-based admin scoping — switch to it.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-5(1), AC-2(3)",
	"cis_rule": "",
	"mitre_technique": "T1552.004",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.servicefabric/clusters"
	props := object.get(resource, "properties", {})
	azure_ad := object.get(props, "azureActiveDirectory", {})
	tenant_id := object.get(azure_ad, "tenantId", "")
	tenant_id == ""

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Service Fabric cluster '%s' does not have an azureActiveDirectory block. Migrate admin auth from certificate thumbprints to Entra ID.", [resource.name]),
		"evidence": {"azureActiveDirectoryTenantId": tenant_id},
		"chain_role": metadata.chain_role,
	}
}
