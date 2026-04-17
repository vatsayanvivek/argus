package argus.azure.zt.zt_ai_002

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "zt_ai_002",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Identity",
	"title": "Cognitive Services account relies on shared subscription keys (local auth enabled)",
	"description": "Cognitive Services accounts with local authentication enabled are authenticated via static subscription keys. Keys are long-lived shared secrets that appear in logs, CI variables, and client-side code — any leak gives durable access. Entra ID auth with managed identities eliminates the shared-secret attack surface.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-5(1), AC-2(3)",
	"cis_rule": "",
	"mitre_technique": "T1552.001",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.cognitiveservices/accounts"
	props := object.get(resource, "properties", {})
	local_auth_disabled := object.get(props, "disableLocalAuth", false)
	local_auth_disabled == false

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Cognitive Services account '%s' accepts authentication via shared subscription keys. Migrate callers to Entra ID tokens via managed identity and set disableLocalAuth=true.", [resource.name]),
		"evidence": {
			"disableLocalAuth": local_auth_disabled,
			"kind": object.get(resource, "kind", ""),
		},
		"chain_role": metadata.chain_role,
	}
}
