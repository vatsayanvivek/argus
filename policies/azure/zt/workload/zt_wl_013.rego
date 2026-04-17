package argus.azure.zt.workload.zt_wl_013

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_013",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "Container Registry allows public network access",
    "description": "Container Registries that do not disable public network access are reachable from the internet, expanding the attack surface for image pull/push operations. Restricting access to private endpoints limits exposure to trusted networks only.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Monitor and measure integrity and security posture of assets",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    r := input.resources[_]
    r.type == "Microsoft.ContainerRegistry/registries"
    props := object.get(r, "properties", {})
    pna := object.get(props, "publicNetworkAccess", "Enabled")
    pna != "Disabled"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(r, "id", ""),
        "resource_type": "Microsoft.ContainerRegistry/registries",
        "resource_name": object.get(r, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Container Registry '%s' has publicNetworkAccess='%s' (not Disabled).", [object.get(r, "name", ""), pna]),
        "evidence": {
            "publicNetworkAccess": pna
        },
        "chain_role": metadata.chain_role
    }
}
