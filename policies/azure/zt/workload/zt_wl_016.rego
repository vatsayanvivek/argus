package argus.azure.zt.workload.zt_wl_016

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_016",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "AKS cluster does not enforce pod security standards",
    "description": "AKS clusters without pod security policies or the Azure Policy add-on allow containers to run with elevated privileges, host networking, or other dangerous capabilities. Enforcing pod security standards limits container escape and lateral movement.",
    "zt_tenet": "Tenet 7",
    "nist_800_207": "Tenet 7 - Collect information about the current state of assets",
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
    not has_pod_security(props)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(cluster, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(cluster, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' does not enforce pod security standards (no pod security policy and no Azure Policy add-on).", [object.get(cluster, "name", "")]),
        "evidence": {
            "podSecurityPolicy": object.get(props, "podSecurityPolicy", null),
            "azurePolicyAddonEnabled": addon_enabled(props)
        },
        "chain_role": metadata.chain_role
    }
}

has_pod_security(props) if {
    object.get(props, "podSecurityPolicy", null) != null
}

has_pod_security(props) if {
    addons := object.get(props, "addonProfiles", {})
    ap := object.get(addons, "azurepolicy", {})
    object.get(ap, "enabled", false) == true
}

addon_enabled(props) := val if {
    addons := object.get(props, "addonProfiles", {})
    ap := object.get(addons, "azurepolicy", {})
    val := object.get(ap, "enabled", false)
} else := false
