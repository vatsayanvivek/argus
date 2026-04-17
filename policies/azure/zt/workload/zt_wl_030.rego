package argus.azure.zt.zt_wl_030

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_wl_030",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Container App Environment is zone-redundant but has no managed identity",
	"description": "Container App Environments hosting production workloads should authenticate to dependent services (Key Vault, Storage, ACR) via managed identity, not static secrets in env vars. An Environment without a UserAssigned identity forces every Container App inside it to either bake secrets into manifests or fetch them from a shared SAS token — both fail-open designs.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-5(1)",
	"cis_rule": "",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.app/managedenvironments"
	identity := object.get(resource, "identity", {})
	identity_type := object.get(identity, "type", "None")
	identity_type == "None"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Container App Environment '%s' has no managed identity. Attach a UserAssigned identity and use it for KV/Storage/ACR access.", [resource.name]),
		"evidence": {"identityType": identity_type},
		"chain_role": metadata.chain_role,
	}
}
