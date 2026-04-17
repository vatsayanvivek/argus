package argus.azure.cis.cis_9_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_4",
	"source": "argus-cis",
	"severity": "LOW",
	"pillar": "Workload",
	"title": "Ensure App Service has HTTP/2 enabled",
	"description": "HTTP/2 provides improved performance and more robust transport security features over HTTP/1.1.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "SC-8",
	"cis_rule": "9.4",
	"mitre_technique": "T1499",
	"mitre_tactic": "Impact",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	app := input.app_services[_]
	sc := object.get(app.properties, "siteConfig", {})
	h2 := object.get(sc, "http20Enabled", false)
	h2 != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' has HTTP/2 disabled.", [app.name]),
		"evidence": {
			"app_service_id": app.id,
			"http20_enabled": h2,
		},
		"chain_role": metadata.chain_role,
	}
}
