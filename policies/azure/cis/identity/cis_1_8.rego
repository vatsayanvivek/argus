package argus.azure.cis.cis_1_8

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_8",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Identity",
	"title": "Ensure legacy authentication protocols are blocked",
	"description": "Legacy authentication (IMAP, POP, SMTP basic auth, older Office clients) does not support MFA and is the primary vector for password spray attacks.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - All communication secured",
	"nist_800_53": "IA-2",
	"cis_rule": "1.8",
	"mitre_technique": "T1110.003",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	legacy := object.get(input.tenant_settings, "legacy_auth_enabled", false)
	legacy == true
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.AAD/tenantSettings",
		"resource_name": "legacy_auth_enabled",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": "Legacy authentication protocols are enabled on the tenant. These protocols bypass MFA and are trivially brute-forced via password spray.",
		"evidence": {
			"legacy_auth_enabled": legacy,
		},
		"chain_role": metadata.chain_role,
	}
}
