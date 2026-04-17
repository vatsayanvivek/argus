package argus.azure.zt.zt_int_004

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_004",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Logic App workflow accepts HTTP trigger from anywhere with no IP restriction",
	"description": "Logic Apps (Standard or Consumption) with an HTTP trigger are publicly callable by anyone with the URL. The SAS signature in the URL is the only authentication — URL leaks = trivial abuse. Restrict inbound IPs via the workflow's accessControl.triggers block, or put the workflow behind API Management with Entra-ID-authenticated calls.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "AC-4, AC-3(5)",
	"cis_rule": "",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.logic/workflows"
	props := object.get(resource, "properties", {})
	access_control := object.get(props, "accessControl", {})
	triggers := object.get(access_control, "triggers", {})
	allowed := object.get(triggers, "allowedCallerIpAddresses", [])
	count(allowed) == 0

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Logic App workflow '%s' has no caller-IP restriction — the HTTP trigger URL is callable from any internet source. Set accessControl.triggers.allowedCallerIpAddresses.", [resource.name]),
		"evidence": {"allowedCallerIpAddresses": allowed},
		"chain_role": metadata.chain_role,
	}
}
