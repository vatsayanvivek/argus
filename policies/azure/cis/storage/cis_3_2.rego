package argus.azure.cis.cis_3_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_2",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Ensure infrastructure encryption is enabled on storage accounts",
	"description": "Infrastructure encryption provides a second layer of encryption at the infrastructure level in addition to service-level encryption.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - Individual resource access authenticated",
	"nist_800_53": "SC-28(1)",
	"cis_rule": "3.2",
	"mitre_technique": "T1486",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	infra := object.get(sa.properties, "requireInfrastructureEncryption", false)
	infra != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' does not have infrastructure encryption enabled. Double encryption hedges against service-level key compromise.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"requireInfrastructureEncryption": infra,
		},
		"chain_role": metadata.chain_role,
	}
}
