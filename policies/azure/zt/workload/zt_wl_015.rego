package argus.azure.zt.workload.zt_wl_015

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_015",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "AKS cluster does not use Azure RBAC for Kubernetes authorization",
    "description": "AKS clusters without Azure RBAC for Kubernetes authorization rely on local Kubernetes RBAC alone, bypassing Azure AD conditional access and unified audit. Enabling Azure RBAC ties Kubernetes API access to Azure AD identities and policies.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Authentication and authorization are dynamic and strictly enforced",
    "nist_800_53": "AC-3",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    cluster := input.aks_clusters[_]
    props := object.get(cluster, "properties", {})
    aad := object.get(props, "aadProfile", {})
    object.get(aad, "enableAzureRBAC", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(cluster, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(cluster, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' does not use Azure RBAC for Kubernetes authorization.", [object.get(cluster, "name", "")]),
        "evidence": {
            "enableAzureRBAC": object.get(aad, "enableAzureRBAC", false)
        },
        "chain_role": metadata.chain_role
    }
}
