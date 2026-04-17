package argus.azure.zt.zt_int_007

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_007",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "API Management instance has no diagnostic logs routed to Log Analytics or Event Hub",
	"description": "APIM without a diagnostic settings configuration drops audit events (gateway requests, backend failures, policy evaluations) on the floor. Incident response against an API-layer breach needs these logs. Every production APIM instance should route at least 'GatewayLogs' to Log Analytics or Event Hub.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - The enterprise collects as much information as possible about the current state of assets",
	"nist_800_53": "AU-2, AU-12",
	"cis_rule": "",
	"mitre_technique": "T1562.008",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.apimanagement/service"
	resource_id_lower := lower(resource.id)
	# Look for a matching diagnostic setting whose targetResourceId references this APIM.
	not diagnostic_exists(resource_id_lower)

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("APIM service '%s' has no diagnostic settings. Route GatewayLogs + metrics to Log Analytics or Event Hub.", [resource.name]),
		"evidence": {},
		"chain_role": metadata.chain_role,
	}
}

diagnostic_exists(apim_id_lower) if {
	diag := input.resources[_]
	lower(diag.type) == "microsoft.insights/diagnosticsettings"
	target := lower(object.get(object.get(diag, "properties", {}), "targetResourceId", ""))
	target == apim_id_lower
}
