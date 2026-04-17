package argus.azure.zt.visibility.zt_vis_001

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_001",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Visibility",
    "title": "Security-relevant resource has no diagnostic settings",
    "description": "Without diagnostic settings streaming to Log Analytics or Event Hub, resource activity is invisible to SOC tooling.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-12",
    "cis_rule": "",
    "mitre_technique": "T1562.008",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    res := input.storage_accounts[_]
    not has_diag(res)
    msg := build_msg(res, "Microsoft.Storage/storageAccounts")
}

violation contains msg if {
    res := input.sql_servers[_]
    not has_diag(res)
    msg := build_msg(res, "Microsoft.Sql/servers")
}

violation contains msg if {
    res := input.key_vaults[_]
    not has_diag(res)
    msg := build_msg(res, "Microsoft.KeyVault/vaults")
}

violation contains msg if {
    res := input.virtual_machines[_]
    not has_diag(res)
    msg := build_msg(res, "Microsoft.Compute/virtualMachines")
}

violation contains msg if {
    res := input.aks_clusters[_]
    not has_diag(res)
    msg := build_msg(res, "Microsoft.ContainerService/managedClusters")
}

has_diag(res) if {
    rid := object.get(res, "id", "")
    ds := object.get(input, "diagnostic_settings", {})
    object.get(ds, rid, false) == true
}

build_msg(res, rtype) := msg if {
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(res, "id", ""),
        "resource_type": rtype,
        "resource_name": object.get(res, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("%s '%s' has no diagnostic settings configured.", [rtype, object.get(res, "name", "")]),
        "evidence": {
            "diagnostic_settings_enabled": false
        },
        "chain_role": metadata.chain_role
    }
}
