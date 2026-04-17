package argus.azure.zt.zt_data_030

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "zt_data_030",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Data",
	"title": "NetApp volume permits NFS v3 (no Kerberos) from mount endpoints",
	"description": "NetApp NFS v3 volumes authenticate clients solely by source IP — there is no per-user authentication on the wire. Any workload whose NIC IP is in the export policy mounts the volume and reads every file. NFS v4.1 with Kerberos adds strong per-user auth; v3 exports should only exist for workloads that cannot support v4.1 and must be tightly restricted by subnet.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - All resource authentication is dynamic and strictly enforced",
	"nist_800_53": "IA-2, AC-3",
	"cis_rule": "",
	"mitre_technique": "T1005",
	"mitre_tactic": "Collection",
	"chain_role": "AMPLIFIER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.netapp/netappaccounts/capacitypools/volumes"
	props := object.get(resource, "properties", {})
	protocols := object.get(props, "protocolTypes", [])
	some proto in protocols
	proto == "NFSv3"

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("NetApp volume '%s' exposes NFSv3 (no per-user auth). Migrate callers to NFSv4.1 + Kerberos.", [resource.name]),
		"evidence": {"protocolTypes": protocols},
		"chain_role": metadata.chain_role,
	}
}
