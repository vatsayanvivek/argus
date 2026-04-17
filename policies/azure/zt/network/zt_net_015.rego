package argus.azure.zt.network.zt_net_015

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_015",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "VPN Gateway not using IKEv2 or OpenVPN protocol",
    "description": "VPN gateways using only SSTP or IKEv1 are limited to older, less secure protocols. IKEv2 and OpenVPN provide stronger encryption, faster reconnection, and broader platform support. Missing IKEv2 may indicate use of deprecated protocols vulnerable to downgrade attacks.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-8(1)",
    "cis_rule": "",
    "mitre_technique": "T1557",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    res := input.resources[_]
    object.get(res, "type", "") == "Microsoft.Network/virtualNetworkGateways"
    props := object.get(res, "properties", {})
    vpn_config := object.get(props, "vpnClientConfiguration", {})
    protocols := object.get(vpn_config, "vpnClientProtocols", [])
    not protocol_includes_ikev2(protocols)
    name := object.get(res, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(res, "id", ""),
        "resource_type": "Microsoft.Network/virtualNetworkGateways",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VPN Gateway '%s' does not include IKEv2 in its client protocols: %s. This may indicate use of deprecated protocols.", [name, concat(", ", protocols)]),
        "evidence": {
            "gateway_name": name,
            "vpnClientProtocols": protocols
        },
        "chain_role": metadata.chain_role
    }
}

protocol_includes_ikev2(protocols) if {
    protocols[_] == "IkeV2"
}
