package argus.azure.cis.cis_5_1

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_1",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure a diagnostic setting exists at subscription scope",
	"description": "A subscription-scoped diagnostic setting captures the Azure Activity Log for audit and detection. Without it you lose authoritative control plane telemetry.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-2",
	"cis_rule": "5.1",
	"mitre_technique": "T1562.008",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	diag := object.get(input.diagnostic_settings, input.subscription.id, false)
	diag != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Subscription/subscription",
		"resource_name": input.subscription.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no diagnostic setting forwarding the Activity Log. Control plane events are not retained.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"diagnostic_settings_enabled": diag,
		},
		"chain_role": metadata.chain_role,
	}
}
