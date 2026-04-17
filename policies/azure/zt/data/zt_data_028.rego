package argus.azure.zt.zt_data_028

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_028",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Synapse Dedicated SQL Pool has no Transparent Data Encryption",
	"description": "Synapse Dedicated SQL pools contain warehouse data that commonly includes customer PII, transaction history, and analytic aggregates. Without TDE enabled, the on-disk storage for the pool is unencrypted — any stolen database-file backup is readable in cleartext. TDE is free, has zero performance cost on modern storage, and is expected by every audit.",
	"zt_tenet": "Tenet 4",
	"nist_800_207": "Tenet 4 - Access to individual enterprise resources is granted on a per-session basis",
	"nist_800_53": "SC-28(1)",
	"cis_rule": "",
	"mitre_technique": "T1005",
	"mitre_tactic": "Collection",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.synapse/workspaces/sqlpools"
	props := object.get(resource, "properties", {})
	# Synapse TDE status lives under the child resource
	# /transparentDataEncryption — if the parent's properties don't
	# already confirm Enabled, flag it pending a child lookup.
	status := object.get(props, "transparentDataEncryption", "Disabled")
	status != "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Synapse dedicated SQL pool '%s' TDE status is '%s' (not Enabled). Enable transparent data encryption.", [resource.name, status]),
		"evidence": {"transparentDataEncryption": status},
		"chain_role": metadata.chain_role,
	}
}
