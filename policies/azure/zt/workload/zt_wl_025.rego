package argus.azure.zt.zt_wl_025

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_wl_025",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Container App is externally-ingressed and allows insecure HTTP",
	"description": "Container Apps with external ingress reach the public internet via Azure's shared ingress. When allowInsecureConnections is true, HTTP-without-TLS is accepted, enabling downgrade attacks and cleartext credential capture. For any external-facing Container App, TLS must be mandatory.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - All communication is secured regardless of network location",
	"nist_800_53": "SC-8, SC-13",
	"cis_rule": "",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.app/containerapps"
	props := object.get(resource, "properties", {})
	config := object.get(props, "configuration", {})
	ingress := object.get(config, "ingress", {})
	external := object.get(ingress, "external", false)
	insecure := object.get(ingress, "allowInsecure", false)
	external == true
	insecure == true

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Container App '%s' has external ingress with allowInsecure=true. Disable HTTP — require HTTPS only.", [resource.name]),
		"evidence": {"external": external, "allowInsecure": insecure},
		"chain_role": metadata.chain_role,
	}
}
