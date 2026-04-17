package argus.azure.zt.workload.zt_wl_022

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_022",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "AKS cluster does not use Key Vault CSI driver for secrets",
    "description": "AKS clusters without the Azure Key Vault Secrets Provider add-on store secrets as Kubernetes Secrets, which are base64-encoded but not encrypted at the application layer. Using the Key Vault CSI driver ensures secrets are fetched directly from Key Vault and never persisted in etcd.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "SC-12",
    "cis_rule": "",
    "mitre_technique": "T1552",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    cluster := input.aks_clusters[_]
    props := object.get(cluster, "properties", {})
    addons := object.get(props, "addonProfiles", {})
    kvp := object.get(addons, "azureKeyvaultSecretsProvider", {})
    object.get(kvp, "enabled", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(cluster, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(cluster, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' does not have the Key Vault CSI driver (azureKeyvaultSecretsProvider) enabled.", [object.get(cluster, "name", "")]),
        "evidence": {
            "azureKeyvaultSecretsProviderEnabled": object.get(kvp, "enabled", false)
        },
        "chain_role": metadata.chain_role
    }
}
