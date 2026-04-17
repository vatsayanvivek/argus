package argus.azure.cis.cis_9_13

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_13",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "App Service uses managed identity for authentication",
	"description": "App Services without managed identity must store credentials in configuration or code. Managed identity eliminates credential management and reduces the risk of credential leakage.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "IA-2",
	"cis_rule": "9.13",
	"mitre_technique": "T1078",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_managed_identity(app) if {
	identity := object.get(app, "identity", {})
	t := object.get(identity, "type", "None")
	t != "None"
}

violation contains msg if {
	app := input.app_services[_]
	not has_managed_identity(app)
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' does not use managed identity. Credentials are likely stored in app configuration or code.", [app.name]),
		"evidence": {
			"app_service_id": app.id,
			"identity_type": object.get(object.get(app, "identity", {}), "type", "None"),
		},
		"chain_role": metadata.chain_role,
	}
}
