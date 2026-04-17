package argus.azure.zt.workload.zt_wl_007

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_007",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "AKS cluster allows privileged containers",
    "description": "AKS clusters without Azure Policy or pod security enforcement can run privileged containers that break out to the node and escalate to cluster admin.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AC-6",
    "cis_rule": "",
    "mitre_technique": "T1611",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    aks := input.aks_clusters[_]
    props := object.get(aks, "properties", {})
    not has_policy_addon(props)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(aks, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(aks, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' has no Azure Policy or pod security enforcement configured — privileged containers are allowed.", [object.get(aks, "name", "")]),
        "evidence": {
            "addonProfiles": object.get(props, "addonProfiles", {}),
            "podSecurityPolicy": object.get(props, "podSecurityPolicy", null)
        },
        "chain_role": metadata.chain_role
    }
}

has_policy_addon(props) if {
    addons := object.get(props, "addonProfiles", {})
    ap := object.get(addons, "azurepolicy", {})
    object.get(ap, "enabled", false) == true
}

has_policy_addon(props) if {
    psp := object.get(props, "podSecurityPolicy", null)
    psp != null
    psp != ""
}
