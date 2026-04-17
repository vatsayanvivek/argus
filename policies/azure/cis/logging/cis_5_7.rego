package argus.azure.cis.cis_5_7

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_5_7",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Azure Monitor Diagnostic Settings captures all categories",
	"description": "Diagnostic settings must capture all log categories to ensure complete visibility. Missing categories create blind spots that attackers can exploit to evade detection.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "AU-12",
	"cis_rule": "5.7",
	"mitre_technique": "T1562",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	ts := object.get(input, "tenant_settings", {})
	diag := object.get(ts, "diagnostic_settings_all_categories", false)
	diag != true
	sub := object.get(input, "subscription", {})
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(sub, "id", ""),
		"resource_type": "Microsoft.Insights/diagnosticSettings",
		"resource_name": object.get(sub, "display_name", "subscription"),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' diagnostic settings do not capture all log categories. Detection blind spots exist.", [object.get(sub, "display_name", "subscription")]),
		"evidence": {
			"all_categories_enabled": false,
		},
		"chain_role": metadata.chain_role,
	}
}
