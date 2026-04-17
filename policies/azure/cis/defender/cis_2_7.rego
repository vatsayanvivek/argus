package argus.azure.cis.cis_2_7

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_7",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Visibility",
	"title": "Ensure Microsoft Defender for DNS is set to Standard",
	"description": "Defender for DNS detects DNS-based data exfiltration, beaconing to known C2 infrastructure, and name resolution to malicious domains.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Asset posture collection",
	"nist_800_53": "SI-4",
	"cis_rule": "2.7",
	"mitre_technique": "T1071.004",
	"mitre_tactic": "Command and Control",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	plan := object.get(input.defender_plans, "dns", "Free")
	plan != "Standard"
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Security/pricings",
		"resource_name": "Dns",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Defender for DNS is '%v' on subscription '%v'. DNS tunneling and malicious lookups will go undetected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "dns",
		},
		"chain_role": metadata.chain_role,
	}
}
