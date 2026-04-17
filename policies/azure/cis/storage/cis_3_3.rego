package argus.azure.cis.cis_3_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_3",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Data",
	"title": "Ensure public blob access is disabled on storage accounts",
	"description": "Storage accounts with allowBlobPublicAccess=true permit anonymous reads of any container configured as Blob or Container public access. This is a primary cause of cloud data breaches.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - Per-session authenticated access",
	"nist_800_53": "AC-3",
	"cis_rule": "3.3",
	"mitre_technique": "T1530",
	"mitre_tactic": "Collection",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	allow := object.get(sa.properties, "allowBlobPublicAccess", true)
	allow == true
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' permits public blob access at the account level. Any container can be exposed anonymously.", [sa.name]),
		"evidence": {
			"storage_account_id": sa.id,
			"allowBlobPublicAccess": allow,
		},
		"chain_role": metadata.chain_role,
	}
}
