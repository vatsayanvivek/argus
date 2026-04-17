package argus.azure.cis.cis_5_2

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_2",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure Activity Log retention is 365 days or more",
	"description": "The Activity Log should be retained for at least 365 days to support investigation of incidents that are discovered months after the fact.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Continuous monitoring",
	"nist_800_53": "AU-11",
	"cis_rule": "5.2",
	"mitre_technique": "T1070",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

has_retention_meta if {
	evt := input.activity_log[_]
	retention := object.get(evt, "retention_days", 0)
	retention >= 365
}

violation contains msg if {
	not has_retention_meta
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Insights/diagnosticSettings",
		"resource_name": "activity_log_retention",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no Activity Log entries with retention >= 365 days. Configure a log profile or diagnostic setting with 365+ day retention.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"activity_log_entries": count(input.activity_log),
		},
		"chain_role": metadata.chain_role,
	}
}
