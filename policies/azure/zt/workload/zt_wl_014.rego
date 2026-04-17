package argus.azure.zt.workload.zt_wl_014

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_014",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "AKS cluster has no network policy configured",
    "description": "AKS clusters without a network policy engine (calico or azure) allow unrestricted pod-to-pod communication, enabling lateral movement after initial compromise of any workload in the cluster.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Monitor and measure integrity and security posture of assets",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1046",
    "mitre_tactic": "Discovery",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    cluster := input.aks_clusters[_]
    props := object.get(cluster, "properties", {})
    np := object.get(props, "networkProfile", {})
    policy := object.get(np, "networkPolicy", "")
    policy == ""
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(cluster, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(cluster, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' has no network policy configured, allowing unrestricted pod-to-pod traffic.", [object.get(cluster, "name", "")]),
        "evidence": {
            "networkPolicy": policy
        },
        "chain_role": metadata.chain_role
    }
}
