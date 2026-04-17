package argus.azure.zt.visibility.zt_vis_019

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_vis_019",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Application Insights not configured for web applications",
	"description": "Application Insights provides request tracing, dependency tracking, and exception logging for web apps. Without it, application-layer attacks such as injection and exploitation go undetected.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Integrity monitored",
	"nist_800_53": "AU-12",
	"cis_rule": "",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

has_app_insights(app) if {
	cfg := object.get(object.get(app, "properties", {}), "siteConfig", {})
	object.get(cfg, "appInsightsEnabled", false) == true
}

has_app_insights(app) if {
	cfg := object.get(object.get(app, "properties", {}), "siteConfig", {})
	settings := object.get(cfg, "appSettings", [])
	setting := settings[_]
	object.get(setting, "name", "") == "APPINSIGHTS_INSTRUMENTATIONKEY"
	object.get(setting, "value", "") != ""
}

violation contains msg if {
	app := input.app_services[_]
	not has_app_insights(app)
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(app, "id", ""),
		"resource_type": "Microsoft.Web/sites",
		"resource_name": object.get(app, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' does not have Application Insights configured. Application-layer attacks will not be detected.", [object.get(app, "name", "")]),
		"evidence": {
			"app_service_id": object.get(app, "id", ""),
			"app_insights_enabled": false,
		},
		"chain_role": metadata.chain_role,
	}
}
