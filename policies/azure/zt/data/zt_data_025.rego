package argus.azure.zt.zt_data_025

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_025",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Data",
	"title": "Stream Analytics job lacks customer-managed key encryption",
	"description": "Stream Analytics jobs buffer event-stream data on Microsoft-managed disks during processing. Without a customer-managed key configured in the job's identity + keyVaultProperties, that buffer is encrypted with Microsoft keys by default. For regulated streams (payment events, health telemetry, financial trades), the SOC 2 + HIPAA + PCI auditors require the customer to own the encryption key material.",
	"zt_tenet": "Tenet 4",
	"nist_800_207": "Tenet 4 - Access to individual enterprise resources is granted on a per-session basis",
	"nist_800_53": "SC-12, SC-28",
	"cis_rule": "",
	"mitre_technique": "T1552",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.streamanalytics/streamingjobs"
	props := object.get(resource, "properties", {})
	key_vault_props := object.get(props, "keyVaultProperties", {})
	key_name := object.get(key_vault_props, "keyName", "")
	key_name == ""

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Stream Analytics job '%s' has no keyVaultProperties.keyName. Configure a customer-managed key backed by Key Vault.", [resource.name]),
		"evidence": {"keyName": key_name, "keyVaultProperties": key_vault_props},
		"chain_role": metadata.chain_role,
	}
}
