package argus.azure.zt.zt_data_026

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_data_026",
	"source": "argus-zt",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "HDInsight cluster deploys with public gateway enabled",
	"description": "HDInsight clusters with publicNetworkAccess='InboundAndOutbound' or gateway credentials managed by the cluster (not Entra ID) expose the Ambari + WebHCat endpoints to the internet, accepting basic-auth credentials. Attackers who obtain the gateway password have full cluster control. Deploy HDInsight into a VNet with privateOnly access.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "AC-4, SC-7",
	"cis_rule": "",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.hdinsight/clusters"
	props := object.get(resource, "properties", {})
	net_profile := object.get(props, "networkProperties", {})
	public := object.get(net_profile, "publicNetworkAccess", "InboundAndOutbound")
	public != "OutboundOnly"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("HDInsight cluster '%s' has publicNetworkAccess=%s. Set it to 'OutboundOnly' or deploy into a VNet with private endpoints.", [resource.name, public]),
		"evidence": {"publicNetworkAccess": public},
		"chain_role": metadata.chain_role,
	}
}
