package argus.azure.cis.cis_9_1

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_1",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Ensure App Service requires HTTPS only",
	"description": "App Services should redirect all HTTP traffic to HTTPS. Without httpsOnly, sessions and credentials can be captured in transit.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "SC-8",
	"cis_rule": "9.1",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	app := input.app_services[_]
	https_only := object.get(app.properties, "httpsOnly", false)
	https_only != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' accepts plain HTTP traffic. Enable httpsOnly to force TLS.", [app.name]),
		"evidence": {
			"app_service_id": app.id,
			"https_only": https_only,
		},
		"chain_role": metadata.chain_role,
	}
}
