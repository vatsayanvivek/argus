package argus.azure.zt.workload.zt_wl_010

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_010",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "Shared user-assigned managed identity across workloads",
    "description": "User-assigned managed identities shared between multiple workloads violate workload isolation; a compromise of one resource yields all others' permissions.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All resources considered",
    "nist_800_53": "AC-6",
    "cis_rule": "",
    "mitre_technique": "T1134",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    mi := input.managed_identities[_]
    rids := object.get(mi, "resource_ids", [])
    count(rids) > 1
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(mi, "id", ""),
        "resource_type": "Microsoft.ManagedIdentity/userAssignedIdentities",
        "resource_name": object.get(mi, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("User-assigned managed identity '%s' is shared across %d resources.", [object.get(mi, "name", ""), count(rids)]),
        "evidence": {
            "resource_ids": rids,
            "shared_count": count(rids)
        },
        "chain_role": metadata.chain_role
    }
}
