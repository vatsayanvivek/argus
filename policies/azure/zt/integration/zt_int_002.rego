package argus.azure.zt.zt_int_002

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_002",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "API Management lacks a system-assigned managed identity",
	"description": "API Management instances without a managed identity must store backend credentials (Key Vault secrets, storage keys, service principal secrets) inline in named-value stores. System-assigned identity lets APIM fetch secrets from Key Vault at runtime with no static credentials anywhere in the APIM config, collapsing the shared-secret attack surface.",
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
	lower(resource.type) == "microsoft.apimanagement/service"
	identity := object.get(resource, "identity", {})
	object.get(identity, "type", "None") == "None"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("API Management service '%s' has no managed identity configured. Enable SystemAssigned identity and reference backend secrets via Key Vault named-values instead of inline values.", [resource.name]),
		"evidence": {"identityType": object.get(identity, "type", "None")},
		"chain_role": metadata.chain_role,
	}
}
