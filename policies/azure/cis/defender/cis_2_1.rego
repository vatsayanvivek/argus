package argus.azure.cis.cis_2_1

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for Servers is set to Standard",
	"description": "Defender for Servers provides threat detection, vulnerability assessment, and JIT VM access. Without it VMs lack runtime protection.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "SI-4",
	"cis_rule": "2.1",
	"mitre_technique": "T1078",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "virtual_machines", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "VirtualMachines",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for Servers is '%v' on subscription '%v'. VMs lack runtime protection and vulnerability assessment.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "virtual_machines",
		},
		"chain_role": metadata.chain_role,
	}
}
