package argus.azure.cis.cis_9_14

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_14",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "App Service restricts CORS to specific origins",
	"description": "CORS configured with wildcard '*' allows any website to make cross-origin requests. Restricting CORS to specific trusted origins prevents cross-site data theft and CSRF-like attacks.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "AC-4",
	"cis_rule": "9.14",
	"mitre_technique": "T1189",
	"mitre_tactic": "Initial Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	app := input.app_services[_]
	cfg := object.get(object.get(app, "properties", {}), "siteConfig", {})
	cors := object.get(cfg, "cors", {})
	origins := object.get(cors, "allowedOrigins", [])
	origin := origins[_]
	origin == "*"
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' allows CORS from wildcard origin '*'. Any website can make cross-origin requests to this application.", [app.name]),
		"evidence": {
			"app_service_id": app.id,
			"cors_allowed_origins": origins,
		},
		"chain_role": metadata.chain_role,
	}
}
