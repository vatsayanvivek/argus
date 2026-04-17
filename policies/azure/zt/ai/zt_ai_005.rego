package argus.azure.zt.zt_ai_005

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_ai_005",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Azure ML Workspace uses the default Microsoft-managed key",
	"description": "ML Workspaces store training datasets, hyperparameters, and model weights in the associated Storage + Key Vault. By default this encryption uses Microsoft-managed keys. For regulated training data (patient records, financial transactions, proprietary corpora), a customer-managed key via the workspace's encryption property is required to satisfy the HIPAA/SOC 2 auditor that the tenant, not Microsoft, controls key material.",
	"zt_tenet": "Tenet 4",
	"nist_800_207": "Tenet 4 - Access to individual enterprise resources is granted on a per-session basis",
	"nist_800_53": "SC-12, SC-28",
	"cis_rule": "",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.machinelearningservices/workspaces"
	props := object.get(resource, "properties", {})
	encryption := object.get(props, "encryption", {})
	status := object.get(encryption, "status", "Disabled")
	status != "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("ML Workspace '%s' has encryption status '%s' (not Enabled with a Key Vault-backed CMK). Configure workspace encryption with a customer-managed key.", [resource.name, status]),
		"evidence": {"encryptionStatus": status},
		"chain_role": metadata.chain_role,
	}
}
