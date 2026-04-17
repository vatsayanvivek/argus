package argus.azure.cis.cis_9_11

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_11",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "App Service uses latest TLS version",
	"description": "App Services using TLS versions older than 1.2 are vulnerable to protocol downgrade attacks and known cryptographic weaknesses that enable traffic interception.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-8",
	"cis_rule": "9.11",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	app := input.app_services[_]
	cfg := object.get(object.get(app, "properties", {}), "siteConfig", {})
	tls := object.get(cfg, "minTlsVersion", "1.0")
	tls != "1.2"
	tls != "1.3"
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' minimum TLS version is '%v'. TLS 1.2 or higher is required to prevent protocol downgrade attacks.", [app.name, tls]),
		"evidence": {
			"app_service_id": app.id,
			"min_tls_version": tls,
		},
		"chain_role": metadata.chain_role,
	}
}
