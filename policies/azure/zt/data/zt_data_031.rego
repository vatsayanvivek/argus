package argus.azure.zt.zt_data_031

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_031",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Storage Data Lake Gen2 container has no ACL-based access control",
	"description": "Data Lake Gen2 containers use either RBAC (coarse, at container scope) or POSIX ACLs (fine, per-path). Containers with no ACLs configured fall back to blanket RBAC — any user with Storage Blob Data Reader sees every path, even folders meant for specific teams. For lake zones containing cross-team or regulated data, ACLs at the path level are expected. Note: requires Hierarchical Namespace enabled on the account.",
	"zt_tenet": "Tenet 4",
	"nist_800_207": "Tenet 4 - Access to individual enterprise resources is granted on a per-session basis",
	"nist_800_53": "AC-3(7), AC-6",
	"cis_rule": "",
	"mitre_technique": "T1005",
	"mitre_tactic": "Collection",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.storage/storageaccounts"
	props := object.get(resource, "properties", {})
	hns := object.get(props, "isHnsEnabled", false)
	hns == false

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%s' has Hierarchical Namespace disabled. Without HNS, ADLS Gen2 ACLs are unavailable — access falls back to account-wide RBAC.", [resource.name]),
		"evidence": {"isHnsEnabled": hns},
		"chain_role": metadata.chain_role,
	}
}
