package argus.azure.zt.workload.zt_wl_021

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_021",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "Defender for Containers not enabled on AKS cluster",
    "description": "AKS clusters without Microsoft Defender for Containers lack runtime threat detection, vulnerability assessment for container images, and security alerts for suspicious cluster activity. Enabling Defender provides continuous monitoring of the Kubernetes control plane and node-level workloads.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Monitor and measure integrity and security posture of assets",
    "nist_800_53": "SI-4",
    "cis_rule": "",
    "mitre_technique": "T1610",
    "mitre_tactic": "Execution",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    cluster := input.aks_clusters[_]
    props := object.get(cluster, "properties", {})
    sp := object.get(props, "securityProfile", {})
    def := object.get(sp, "defender", {})
    sm := object.get(def, "securityMonitoring", {})
    object.get(sm, "enabled", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(cluster, "id", ""),
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "resource_name": object.get(cluster, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("AKS cluster '%s' does not have Defender for Containers security monitoring enabled.", [object.get(cluster, "name", "")]),
        "evidence": {
            "defenderSecurityMonitoringEnabled": object.get(sm, "enabled", false)
        },
        "chain_role": metadata.chain_role
    }
}
