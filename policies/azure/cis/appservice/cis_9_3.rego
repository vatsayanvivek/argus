package argus.azure.cis.cis_9_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_9_3",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Ensure App Service remote debugging is disabled",
	"description": "Remote debugging allows attaching a debugger from outside Azure. Production App Services must not have remote debugging enabled.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - Monitor posture",
	"nist_800_53": "CM-7",
	"cis_rule": "9.3",
	"mitre_technique": "T1059",
	"mitre_tactic": "Execution",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	app := input.app_services[_]
	sc := object.get(app.properties, "siteConfig", {})
	rde := object.get(sc, "remoteDebuggingEnabled", false)
	rde == true
	msg := {
		"rule_id": metadata.id,
		"resource_id": app.id,
		"resource_type": app.type,
		"resource_name": app.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App Service '%v' has remote debugging enabled. Attackers can attach a debugger and run arbitrary code.", [app.name]),
		"evidence": {
			"app_service_id": app.id,
			"remote_debugging_enabled": rde,
		},
		"chain_role": metadata.chain_role,
	}
}
