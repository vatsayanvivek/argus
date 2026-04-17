package argus.azure.zt.network.zt_net_007

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_007",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "VNet missing DDoS protection",
    "description": "Without DDoS Protection Standard, public-facing workloads in a VNet only receive best-effort platform DDoS mitigation, which is insufficient for critical apps.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-5",
    "cis_rule": "",
    "mitre_technique": "T1499",
    "mitre_tactic": "Impact",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    vnet := input.virtual_networks[_]
    props := object.get(vnet, "properties", {})
    object.get(props, "enableDdosProtection", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vnet, "id", ""),
        "resource_type": "Microsoft.Network/virtualNetworks",
        "resource_name": object.get(vnet, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VNet '%s' does not have DDoS Protection Standard enabled.", [object.get(vnet, "name", "")]),
        "evidence": {
            "enableDdosProtection": object.get(props, "enableDdosProtection", false)
        },
        "chain_role": metadata.chain_role
    }
}
