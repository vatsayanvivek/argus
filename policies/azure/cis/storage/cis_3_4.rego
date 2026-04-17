package argus.azure.cis.cis_3_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_4",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Ensure default network access rule is Deny on storage accounts",
	"description": "Storage accounts should use default-deny network ACLs and explicitly allow trusted subnets or service endpoints. Default-allow exposes data to the entire internet.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "AC-4",
	"cis_rule": "3.4",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	acls := object.get(sa.properties, "networkAcls", {})
	default_action := object.get(acls, "defaultAction", "Allow")
	default_action == "Allow"
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' has networkAcls.defaultAction=Allow, meaning any IP can reach the data plane.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"default_action": default_action,
		},
		"chain_role": metadata.chain_role,
	}
}
