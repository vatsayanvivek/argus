package argus.azure.cis.cis_1_3

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_3",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "Ensure guest users are reviewed on a regular basis",
	"description": "Checks that there is at least one access review covering guest users in the tenant. Stale guest accounts accumulate risk.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Continuous authentication and authorization",
	"nist_800_53": "AC-2(3)",
	"cis_rule": "1.3",
	"mitre_technique": "T1078.004",
	"mitre_tactic": "Persistence",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

guest_review_exists if {
	review := input.access_reviews[_]
	scope := object.get(review, "scope", "")
	contains(lower(scope), "guest")
}

violation contains msg if {
	not guest_review_exists
	count(input.users) > 0
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Subscription/subscription",
		"resource_name": input.subscription.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Tenant under subscription '%v' has no access review covering guest users. Stale B2B guests retain access to resources indefinitely.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"access_reviews_count": count(input.access_reviews),
		},
		"chain_role": metadata.chain_role,
	}
}
