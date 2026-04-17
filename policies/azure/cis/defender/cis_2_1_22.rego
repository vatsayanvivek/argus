package argus.azure.cis.cis_2_1_22

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1_22",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Workload",
	"title": "Defender for Containers not enabled",
	"description": "Defender for Containers provides runtime threat detection, vulnerability assessment, and admission control for AKS clusters and container registries. Without it, container workloads lack runtime protection.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "2.1.22",
	"mitre_technique": "T1610",
	"mitre_tactic": "Execution",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
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
		"detail": sprintf("Defender for Containers is '%v' on subscription '%v'. Container workloads lack runtime threat detection.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "containers",
		},
		"chain_role": metadata.chain_role,
	}
}
