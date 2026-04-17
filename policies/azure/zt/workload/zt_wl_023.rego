package argus.azure.zt.workload.zt_wl_023

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_023",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "AKS cluster does not use private API server",
    "description": "AKS clusters with a public API server endpoint expose the Kubernetes control plane to the internet, allowing unauthenticated reconnaissance and brute-force attacks against the API server.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    cluster := input.aks_clusters[_]
    props := object.get(cluster, "properties", {})
    api_profile := object.get(props, "apiServerAccessProfile", {})
    private := object.get(api_profile, "enablePrivateCluster", false)
    private == false
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(cluster, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(cluster, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' has a public API server endpoint, exposing the Kubernetes control plane to the internet.", [object.get(cluster, "name", "")]),
        "evidence": {
            "enablePrivateCluster": private
        },
        "chain_role": metadata.chain_role
    }
}
