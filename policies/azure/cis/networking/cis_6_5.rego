package argus.azure.cis.cis_6_5

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_5",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure NSG flow logs are enabled",
	"description": "NSG flow logs record IP traffic flowing through network security groups, essential for forensic analysis and detection.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-12",
	"cis_rule": "6.5",
	"mitre_technique": "T1046",
	"mitre_tactic": "Discovery",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	nsg := input.network_security_groups[_]
	diag := object.get(input.diagnostic_settings, nsg.id, false)
	diag != true
	msg := {
		"rule_id": metadata.id,
		"resource_id": nsg.id,
		"resource_type": nsg.type,
		"resource_name": nsg.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("NSG '%v' has no flow logs / diagnostic setting. Forensic network telemetry is unavailable.", [nsg.name]),
		"evidence": {
			"nsg_id": nsg.id,
			"flow_logs_enabled": diag,
		},
		"chain_role": metadata.chain_role,
	}
}
