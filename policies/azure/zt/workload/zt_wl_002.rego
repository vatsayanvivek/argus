package argus.azure.zt.workload.zt_wl_002

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_002",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "Container image pulled from public registry",
    "description": "Images not pulled from a private Azure Container Registry bypass supply chain controls, image scanning, and content trust.",
    "zt_tenet": "Tenet 3",
    "nist_800_207": "Tenet 3 - Access granted per-session",
    "nist_800_53": "SA-12",
    "cis_rule": "",
    "mitre_technique": "T1195",
    "mitre_tactic": "Initial Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    aks := input.aks_clusters[_]
    props := object.get(aks, "properties", {})
    pools := object.get(props, "agentPoolProfiles", [])
    pool := pools[_]
    img := object.get(pool, "nodeImageVersion", "")
    img != ""
    not contains(img, "azurecr.io")
    not contains(img, "mcr.microsoft.com")
    not contains(img, "AKSUbuntu")
    msg := build_msg(aks, "Microsoft.ContainerService/managedClusters", img)
}

violation contains msg if {
    app := input.app_services[_]
    props := object.get(app, "properties", {})
    site_cfg := object.get(props, "siteConfig", {})
    img := object.get(site_cfg, "linuxFxVersion", "")
    startswith(lower(img), "docker|")
    not contains(img, "azurecr.io")
    not contains(img, "mcr.microsoft.com")
    msg := build_msg(app, "Microsoft.Web/sites", img)
}

build_msg(res, rtype, img) := msg if {
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(res, "id", ""),
        "resource_type": rtype,
        "resource_name": object.get(res, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("%s '%s' references image '%s' which is not from an Azure Container Registry.", [rtype, object.get(res, "name", ""), img]),
        "evidence": {
            "image": img
        },
        "chain_role": metadata.chain_role
    }
}
