package argus.azure.cis.cis_2_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_2",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for App Service is set to Standard",
	"description": "Defender for App Service detects attacks against web workloads such as dangling DNS, reverse shell uploads, and suspicious process executions.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Asset posture collection",
	"nist_800_53": "SI-4",
	"cis_rule": "2.2",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "app_services", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "AppServices",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for App Service is '%v' on subscription '%v'. Web apps lack runtime threat detection.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "app_services",
		},
		"chain_role": metadata.chain_role,
	}
}
