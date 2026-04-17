package argus.azure.cis.cis_9_5

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_5",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Workload",
	"title": "Ensure App Service uses managed identity",
	"description": "App Services should authenticate to Azure resources using managed identity instead of connection strings or secrets embedded in configuration.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Dynamic authentication",
	"nist_800_53": "IA-5",
	"cis_rule": "9.5",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
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
		"detail": sprintf("App Service '%v' has no managed identity configured. Secrets are likely embedded in app settings.", [app.name]),
		"evidence": {
			"app_service_id": app.id,
			"identity_type": object.get(object.get(app, "identity", {}), "type", "None"),
		},
		"chain_role": metadata.chain_role,
	}
}
