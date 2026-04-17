package argus.azure.zt.network.zt_net_013

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_013",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "Virtual network has no DDoS protection plan",
    "description": "Azure DDoS Protection Standard provides enhanced mitigation for volumetric, protocol, and application-layer attacks. Without a DDoS protection plan, virtual networks rely only on basic infrastructure-level protection insufficient for targeted attacks.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-5",
    "cis_rule": "",
    "mitre_technique": "T1498",
    "mitre_tactic": "Impact",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    vnet := input.vnets[_]
    object.get(vnet, "ddos_enabled", false) != true
    name := object.get(vnet, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vnet, "id", ""),
        "resource_type": "Microsoft.Network/virtualNetworks",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Virtual network '%s' does not have a DDoS protection plan enabled. Enhanced DDoS mitigation is unavailable.", [name]),
        "evidence": {
            "vnet_name": name,
            "ddos_enabled": false
        },
        "chain_role": metadata.chain_role
    }
}
