package argus.azure.zt.zt_ai_003

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "zt_ai_003",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "Cognitive Services account lacks customer-managed key encryption",
	"description": "Cognitive Services accounts default to Microsoft-managed keys for encryption-at-rest. For workloads processing regulated data (PHI, PII, payment data, proprietary content), customer-managed keys (CMK) stored in Key Vault are required by SOC 2, HIPAA, and PCI for the auditor to confirm the customer, not Microsoft, controls decryption.",
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
	lower(resource.type) == "microsoft.cognitiveservices/accounts"
	props := object.get(resource, "properties", {})
	encryption := object.get(props, "encryption", {})
	key_source := object.get(encryption, "keySource", "Microsoft.CognitiveServices")
	key_source == "Microsoft.CognitiveServices"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Cognitive Services account '%s' uses Microsoft-managed keys (keySource=%s). Configure a Key Vault-backed encryption scope and set keySource=Microsoft.KeyVault for regulatory parity.", [resource.name, key_source]),
		"evidence": {"keySource": key_source, "kind": object.get(resource, "kind", "")},
		"chain_role": metadata.chain_role,
	}
}
