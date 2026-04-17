package argus.azure.zt.zt_int_001

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_int_001",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "API Management instance accepts weak TLS on the gateway",
	"description": "API Management's gateway terminates client TLS and proxies to backend services. A TLS policy that permits 1.0/1.1 or weak ciphers exposes every API behind the gateway to downgrade attacks. Modern clients support TLS 1.2+; there is no legitimate reason to leave weaker protocols enabled on a publicly reachable gateway.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - All communication is secured regardless of network location",
	"nist_800_53": "SC-8, SC-13",
	"cis_rule": "",
	"mitre_technique": "T1557",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

weak_tls_props := [
	"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10",
	"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11",
	"Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30",
]

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.apimanagement/service"
	props := object.get(resource, "properties", {})
	custom := object.get(props, "customProperties", {})
	weak_proto := weak_tls_props[_]
	object.get(custom, weak_proto, "False") == "True"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("API Management service '%s' has a weak TLS protocol enabled on the gateway (%s). Disable TLS 1.0/1.1 and SSL 3.0 and require TLS 1.2+ at minimum.", [resource.name, weak_proto]),
		"evidence": {"enabled_weak_proto": weak_proto, "customProperties": custom},
		"chain_role": metadata.chain_role,
	}
}
