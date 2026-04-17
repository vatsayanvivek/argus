package argus.azure.cis.cis_1_7

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "cis_1_7",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Identity",
	"title": "Ensure no service principal credentials are expired",
	"description": "Service principal passwordCredentials with endDateTime in the past indicate stale credentials that may still exist in configuration files, CI systems, or secret stores.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Dynamic authentication",
	"nist_800_53": "IA-5(1)",
	"cis_rule": "1.7",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

now_ns := time.now_ns()

has_expired_credential(sp) if {
	creds := object.get(sp, "passwordCredentials", [])
	pc := creds[_]
	end_str := object.get(pc, "endDateTime", "")
	end_str != ""
	end_ns := time.parse_rfc3339_ns(end_str)
	end_ns < now_ns
}

violation contains msg if {
	affected := [s | s := input.service_principals[_]; has_expired_credential(s)]
	count(affected) > 0
	sub := object.get(input, "subscription", {})
	tenant_id := object.get(sub, "tenant_id", "unknown")
	sample := [name |
		some i
		i < 25
		name := affected[i].display_name
	]
	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("tenant:%s/expired-sp-credentials", [tenant_id]),
		"resource_type": "Microsoft.AAD/servicePrincipals",
		"resource_name": "tenant",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%d service principal(s) have at least one expired password credential. Rotate or remove stale secrets to reduce credential-theft surface.", [count(affected)]),
		"evidence": {
			"affected_count": count(affected),
			"tenant_id": tenant_id,
			"sample_service_principals": sample,
		},
		"chain_role": metadata.chain_role,
	}
}
