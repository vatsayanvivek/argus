package argus.azure.zt.zt_ai_006

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_ai_006",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Network",
	"title": "Azure ML compute cluster does not enforce SSH to private network",
	"description": "ML compute clusters with remoteLoginPortPublicAccess='Enabled' expose an SSH endpoint on every worker directly to the public internet. Even with strong SSH credentials, this is an unnecessary attack surface for training workloads that normally run autonomously. Keep SSH private and rely on private-endpoint jump-host access if human debugging is needed.",
	"zt_tenet": "Tenet 5",
	"nist_800_207": "Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
	"nist_800_53": "AC-17, SC-7",
	"cis_rule": "",
	"mitre_technique": "T1021.004",
	"mitre_tactic": "Lateral Movement",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.machinelearningservices/workspaces/computes"
	props := object.get(resource, "properties", {})
	compute_props := object.get(props, "properties", {})
	ssh_public := object.get(compute_props, "remoteLoginPortPublicAccess", "NotSpecified")
	ssh_public == "Enabled"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("ML compute '%s' exposes SSH to the public internet (remoteLoginPortPublicAccess=Enabled). Set it to 'Disabled' and reach workers via private endpoints or a VNet jump host.", [resource.name]),
		"evidence": {"remoteLoginPortPublicAccess": ssh_public},
		"chain_role": metadata.chain_role,
	}
}
