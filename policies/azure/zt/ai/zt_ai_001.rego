package argus.azure.zt.zt_ai_001

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "zt_ai_001",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Azure OpenAI / Cognitive Services account is exposed to the public internet",
	"description": "Cognitive Services accounts (including Azure OpenAI deployments) configured with public network access accept inference requests from any source IP. Attackers who obtain (or guess) the subscription key can submit prompts, poison embeddings, or exfiltrate training data from any location — there is no network boundary to contain the blast radius.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "AC-4, SC-7",
	"cis_rule": "",
	"mitre_technique": "T1078.004",
	"mitre_tactic": "Persistence",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.cognitiveservices/accounts"
	props := object.get(resource, "properties", {})
	public := object.get(props, "publicNetworkAccess", "Enabled")
	public == "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Cognitive Services account '%s' (kind=%s) accepts requests from the public internet. Attackers with the subscription key can call inference endpoints from any source IP.", [resource.name, object.get(resource, "kind", "unspecified")]),
		"evidence": {
			"publicNetworkAccess": public,
			"kind": object.get(resource, "kind", ""),
			"custom_subdomain": object.get(props, "customSubDomainName", ""),
		},
		"chain_role": metadata.chain_role,
	}
}
