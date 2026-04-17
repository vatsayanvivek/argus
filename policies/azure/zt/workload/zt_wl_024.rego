package argus.azure.zt.workload.zt_wl_024

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_024",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "AKS cluster does not have Azure Policy add-on enabled",
    "description": "AKS clusters without the Azure Policy add-on cannot enforce organisational guardrails on pod specs, resource limits, or image sources at admission time, leaving compliance enforcement to manual review.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
    "nist_800_53": "CM-7",
    "cis_rule": "",
    "mitre_technique": "T1610",
    "mitre_tactic": "Execution",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    cluster := input.aks_clusters[_]
    props := object.get(cluster, "properties", {})
    addon_profiles := object.get(props, "addonProfiles", {})
    azure_policy := object.get(addon_profiles, "azurepolicy", {})
    enabled := object.get(azure_policy, "enabled", false)
    enabled == false
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(cluster, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(cluster, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' does not have the Azure Policy add-on enabled for admission control enforcement.", [object.get(cluster, "name", "")]),
        "evidence": {
            "azurePolicyEnabled": enabled
        },
        "chain_role": metadata.chain_role
    }
}
