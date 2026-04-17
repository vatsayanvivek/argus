package argus.azure.cis.cis_1_10

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_10",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "Ensure no more than 3 subscription Owners exist",
	"description": "Too many Owner role assignments inflate the blast radius of a credential compromise. Keep no more than 3 Owner assignments per subscription.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Least privilege",
	"nist_800_53": "AC-6(1)",
	"cis_rule": "1.10",
	"mitre_technique": "T1078",
	"mitre_tactic": "Privilege Escalation",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

owner_count := count([ra |
	ra := input.role_assignments[_]
	ra.role_name == "Owner"
])

violation contains msg if {
	owner_count > 3
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Subscription/subscription",
		"resource_name": input.subscription.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has %v Owner role assignments, exceeding the maximum of 3. Reduce standing Owner permissions.", [input.subscription.name, owner_count]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"owner_count": owner_count,
			"max_allowed": 3,
		},
		"chain_role": metadata.chain_role,
	}
}
