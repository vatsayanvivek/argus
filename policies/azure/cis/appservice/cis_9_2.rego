package argus.azure.cis.cis_9_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_2",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Ensure App Service minimum TLS version is 1.2",
	"description": "App Services should require a minimum TLS version of 1.2. Older versions contain known cryptographic weaknesses.",
	"zt_tenet": "Tenet 2",
	"nist_800_207": "Tenet 2 - Secure communication",
	"nist_800_53": "SC-8(1)",
	"cis_rule": "9.2",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	app := input.app_services[_]
	sc := object.get(app.properties, "siteConfig", {})
	tls := object.get(sc, "minTlsVersion", "1.0")
	tls < "1.2"
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' minTlsVersion is '%v'. Upgrade to 1.2 or higher.", [app.name, tls]),
		"evidence": {
			"app_service_id": app.id,
			"min_tls_version": tls,
		},
		"chain_role": metadata.chain_role,
	}
}
