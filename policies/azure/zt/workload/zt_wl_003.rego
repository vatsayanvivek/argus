package argus.azure.zt.workload.zt_wl_003

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_003",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Workload",
    "title": "AKS API server is publicly reachable without IP allowlist",
    "description": "AKS clusters with a public API endpoint and no authorized IP ranges (or wildcard ranges) expose the Kubernetes control plane to the Internet.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    aks := input.aks_clusters[_]
    props := object.get(aks, "properties", {})
    api := object.get(props, "apiServerAccessProfile", {})
    object.get(api, "enablePrivateCluster", false) != true
    is_unrestricted(api)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(aks, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(aks, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' has public API server and no authorized IP ranges.", [object.get(aks, "name", "")]),
        "evidence": {
            "enablePrivateCluster": object.get(api, "enablePrivateCluster", false),
            "authorizedIPRanges": object.get(api, "authorizedIPRanges", [])
        },
        "chain_role": metadata.chain_role
    }
}

is_unrestricted(api) if {
    ranges := object.get(api, "authorizedIPRanges", [])
    count(ranges) == 0
}

is_unrestricted(api) if {
    ranges := object.get(api, "authorizedIPRanges", [])
    ranges[_] == "0.0.0.0/0"
}
