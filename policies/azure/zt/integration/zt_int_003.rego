package argus.azure.zt.zt_int_003

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_003",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Identity",
	"title": "Event Grid / Service Bus / Event Hub namespace allows local auth (SAS keys)",
	"description": "Messaging namespaces (Event Grid, Service Bus, Event Hub) with local authentication enabled accept SAS-key authentication. SAS keys are static, long-lived, and commonly end up in environment variables, CI secrets, and config repos. Disabling local auth forces every publisher and subscriber to use Entra ID tokens via managed identity, eliminating the shared-secret risk class.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-5(1), AC-2(3)",
	"cis_rule": "",
	"mitre_technique": "T1552.001",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

messaging_types := [
	"microsoft.eventgrid/topics",
	"microsoft.eventgrid/domains",
	"microsoft.eventhub/namespaces",
	"microsoft.servicebus/namespaces",
]

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == messaging_types[_]
	props := object.get(resource, "properties", {})
	disable_local := object.get(props, "disableLocalAuth", false)
	disable_local == false

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("%s '%s' permits SAS-key authentication (disableLocalAuth=false). Move publishers/subscribers to Entra ID + managed identity and set disableLocalAuth=true.", [resource.type, resource.name]),
		"evidence": {"disableLocalAuth": disable_local},
		"chain_role": metadata.chain_role,
	}
}
