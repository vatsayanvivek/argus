package argus.azure.zt.zt_net_023

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_net_023",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "ExpressRoute circuit does not use MACsec encryption",
	"description": "ExpressRoute circuits without MACsec (configured via adminState='Enabled' on linkFeatures.macSec) carry customer traffic between Microsoft's edge and the on-prem provider without link-layer encryption. Any physical-layer tap on the shared fibre between the meet-me point and your provider edge reads the traffic. MACsec is free and available on ExpressRoute Direct — enable it.",
	"zt_tenet": "Tenet 3",
	"nist_800_207": "Tenet 3 - All communication is secured regardless of network location",
	"nist_800_53": "SC-8",
	"cis_rule": "",
	"mitre_technique": "T1040",
	"mitre_tactic": "Credential Access",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.network/expressrouteports"
	props := object.get(resource, "properties", {})
	link_features := object.get(props, "linkFeatures", {})
	macsec := object.get(link_features, "macSec", {})
	state := object.get(macsec, "adminState", "Disabled")
	state != "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("ExpressRoute Direct port '%s' has MACsec adminState=%s. Enable MACsec to encrypt the physical link.", [resource.name, state]),
		"evidence": {"macSecAdminState": state},
		"chain_role": metadata.chain_role,
	}
}
