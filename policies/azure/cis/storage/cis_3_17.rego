package argus.azure.cis.cis_3_17

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_3_17",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Storage account minimum TLS version is 1.2",
	"description": "Storage accounts accepting TLS versions older than 1.2 are vulnerable to protocol downgrade attacks and known cryptographic weaknesses that enable traffic interception and credential theft.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-8",
	"cis_rule": "3.17",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	sa := input.storage_accounts[_]
	tls := object.get(object.get(sa, "properties", {}), "minimumTlsVersion", "TLS1_0")
	tls != "TLS1_2"
	tls != "TLS1_3"
	msg := {
		"rule_id": metadata.id,
		"resource_id": sa.id,
		"resource_type": sa.type,
		"resource_name": sa.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Storage account '%v' minimum TLS version is '%v'. TLS 1.2 or higher is required to prevent protocol downgrade attacks.", [sa.name, tls]),
		"evidence": {
			"storage_account_id": sa.id,
			"minimum_tls_version": tls,
		},
		"chain_role": metadata.chain_role,
	}
}
