package argus.azure.cis.cis_3_1

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_1",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Ensure 'Secure transfer required' is enabled on storage accounts",
	"description": "Storage accounts should only accept connections over HTTPS. HTTP traffic to blob/table/queue endpoints is trivially interceptable.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - All communication secured regardless of network",
	"nist_800_53": "SC-8",
	"cis_rule": "3.1",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	https_only := object.get(sa.properties, "supportsHttpsTrafficOnly", false)
	https_only == false
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' accepts HTTP traffic. Credentials and data can be captured on the wire.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"supportsHttpsTrafficOnly": https_only,
		},
		"chain_role": metadata.chain_role,
	}
}
