package argus.azure.zt.zt_wl_026

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_wl_026",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "App Configuration store allows local authentication (access keys)",
	"description": "App Configuration stores with local authentication enabled accept static access keys — long-lived shared secrets that end up in CI variables, config repos, and logs. Every key leak gives durable read/write access to every feature flag + config value in the store. Disable local auth and force callers to use Entra ID + managed identity.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-5(1)",
	"cis_rule": "",
	"mitre_technique": "T1552.001",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.appconfiguration/configurationstores"
	props := object.get(resource, "properties", {})
	disable_local := object.get(props, "disableLocalAuth", false)
	disable_local == false

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Configuration store '%s' allows local authentication. Set disableLocalAuth=true and move clients to managed identity.", [resource.name]),
		"evidence": {"disableLocalAuth": disable_local},
		"chain_role": metadata.chain_role,
	}
}
