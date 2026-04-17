package argus.azure.cis.cis_2_1_24

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_2_1_24",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "Defender for DNS not enabled",
	"description": "Defender for DNS detects suspicious DNS queries including communication with command-and-control servers, data exfiltration via DNS tunneling, and domain generation algorithms.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "2.1.24",
	"mitre_technique": "T1071",
	"mitre_tactic": "Command and Control",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
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
		"detail": sprintf("Defender for DNS is '%v' on subscription '%v'. Malicious DNS activity such as C2 communication and tunneling will not be detected.", [plan, input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"defender_plan": plan,
			"service": "dns",
		},
		"chain_role": metadata.chain_role,
	}
}
