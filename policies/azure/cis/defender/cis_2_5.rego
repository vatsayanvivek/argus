package argus.azure.cis.cis_2_5

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_5",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for Containers is set to Standard",
	"description": "Defender for Containers scans container images for vulnerabilities and detects runtime threats in AKS clusters.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Asset posture collection",
	"nist_800_53": "SI-4",
	"cis_rule": "2.5",
	"mitre_technique": "T1610",
	"mitre_tactic": "Execution",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "containers", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "Containers",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for Containers is '%v' on subscription '%v'. Clusters lack image scanning and runtime threat detection.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "containers",
		},
		"chain_role": metadata.chain_role,
	}
}
