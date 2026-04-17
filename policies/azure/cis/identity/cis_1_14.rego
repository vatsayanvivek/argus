package argus.azure.cis.cis_1_14

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_14",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "Ensure Privileged Identity Management (PIM) is in use",
	"description": "PIM provides just-in-time elevation and reduces standing privileged access. Tenants should have at least some eligible (non-permanent) assignments configured.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Just-in-time access",
	"nist_800_53": "AC-6(2)",
	"cis_rule": "1.14",
	"mitre_technique": "T1078",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

has_eligible if {
	pa := input.pim_assignments[_]
	pa.assignment_type == "Eligible"
}

violation contains msg if {
	not has_eligible
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Subscription/subscription",
		"resource_name": input.subscription.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no PIM eligible assignments configured. All privileged access is standing, increasing exposure window.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"pim_assignments_count": count(input.pim_assignments),
		},
		"chain_role": metadata.chain_role,
	}
}
