package argus.azure.zt.network.zt_net_020

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_020",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "Virtual network peering allows forwarded traffic from remote",
    "description": "VNet peering with allowForwardedTraffic enabled lets the remote network forward traffic from third-party networks into the local VNet, bypassing local egress controls. This can be abused for lateral movement or to route command-and-control traffic through a trusted peering.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7(5)",
    "cis_rule": "",
    "mitre_technique": "T1090",
    "mitre_tactic": "Command and Control",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    res := input.resources[_]
    object.get(res, "type", "") == "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"
    props := object.get(res, "properties", {})
    object.get(props, "allowForwardedTraffic", false) == true
    name := object.get(res, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(res, "id", ""),
        "resource_type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VNet peering '%s' allows forwarded traffic from the remote network, enabling third-party traffic to enter the local virtual network.", [name]),
        "evidence": {
            "peering_name": name,
            "allowForwardedTraffic": true,
            "remoteVirtualNetwork": object.get(props, "remoteVirtualNetwork", {})
        },
        "chain_role": metadata.chain_role
    }
}
