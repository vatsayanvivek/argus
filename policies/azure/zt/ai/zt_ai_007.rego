package argus.azure.zt.zt_ai_007

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_ai_007",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Workload",
	"title": "Bot Service endpoint lacks managed identity authentication",
	"description": "Azure Bot Service instances that rely on application-password authentication to Bot Framework store the secret in the bot's web-app setting (MicrosoftAppPassword). This is a long-lived static credential. Modern Bot Service supports 'UserAssignedMSI' or 'SystemAssignedMSI' — switch to managed identity so Bot Framework token acquisition uses Entra ID, with no static secret on the bot's config.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-5(1)",
	"cis_rule": "",
	"mitre_technique": "T1552.001",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.botservice/botservices"
	props := object.get(resource, "properties", {})
	app_type := object.get(props, "msaAppType", "MultiTenant")
	app_type != "SystemAssignedMSI"
	app_type != "UserAssignedMSI"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Bot Service '%s' uses msaAppType=%s — still relies on a static MicrosoftAppPassword. Switch to SystemAssignedMSI or UserAssignedMSI.", [resource.name, app_type]),
		"evidence": {"msaAppType": app_type},
		"chain_role": metadata.chain_role,
	}
}
