package argus.azure.cis.cis_2_1_25

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1_25",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Defender for Resource Manager not enabled",
	"description": "Defender for Resource Manager monitors ARM operations for suspicious activity such as anomalous resource deployments, privilege escalation, and lateral movement at the control plane.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "2.1.25",
	"mitre_technique": "T1078",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
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
		"detail": sprintf("Defender for Resource Manager is '%v' on subscription '%v'. ARM-layer attacks will go undetected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "arm",
		},
		"chain_role": metadata.chain_role,
	}
}
