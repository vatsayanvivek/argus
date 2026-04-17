package argus.azure.cis.cis_2_8

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_8",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for Resource Manager is set to Standard",
	"description": "Defender for Resource Manager detects suspicious ARM operations such as credential dumping, resource creation in unusual regions, and anomalous role assignments.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Asset posture collection",
	"nist_800_53": "SI-4",
	"cis_rule": "2.8",
	"mitre_technique": "T1098",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "arm", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "Arm",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for Resource Manager is '%v' on subscription '%v'. ARM-layer attacks like privilege escalation will go undetected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "arm",
		},
		"chain_role": metadata.chain_role,
	}
}
