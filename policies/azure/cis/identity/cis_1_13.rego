package argus.azure.cis.cis_1_13

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_13",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "Ensure access reviews exist for privileged roles",
	"description": "Azure AD Access Reviews should be configured to periodically validate continued need for privileged role assignments.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Continuous authorization review",
	"nist_800_53": "AC-2(3)",
	"cis_rule": "1.13",
	"mitre_technique": "T1078",
	"mitre_tactic": "Persistence",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

priv_review_exists if {
	review := input.access_reviews[_]
	scope := object.get(review, "scope", "")
	contains(lower(scope), "privileged")
}

priv_review_exists if {
	review := input.access_reviews[_]
	scope := object.get(review, "scope", "")
	contains(lower(scope), "admin")
}

violation contains msg if {
	not priv_review_exists
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Subscription/subscription",
		"resource_name": input.subscription.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("No access reviews configured for privileged/admin roles in subscription '%v'. Standing privileged access drifts over time.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"access_reviews_count": count(input.access_reviews),
		},
		"chain_role": metadata.chain_role,
	}
}
