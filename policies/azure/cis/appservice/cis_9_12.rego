package argus.azure.cis.cis_9_12

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_12",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "App Service disables FTP deployment",
	"description": "FTP transmits credentials and code in plaintext. App Services should use FTPS or disable FTP entirely to prevent credential theft and code tampering during deployment.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "CM-7",
	"cis_rule": "9.12",
	"mitre_technique": "T1071",
	"mitre_tactic": "Command and Control",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	app := input.app_services[_]
	cfg := object.get(object.get(app, "properties", {}), "siteConfig", {})
	ftp := object.get(cfg, "ftpsState", "AllAllowed")
	ftp != "Disabled"
	ftp != "FtpsOnly"
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' has FTP state '%v'. FTP should be disabled or restricted to FTPS only to prevent plaintext credential exposure.", [app.name, ftp]),
		"evidence": {
			"app_service_id": app.id,
			"ftps_state": ftp,
		},
		"chain_role": metadata.chain_role,
	}
}
