package argus.azure.zt.network.zt_net_004

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_004",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "VNet peering without central firewall inspection",
    "description": "Peered VNets that transit without a central firewall (hub-and-spoke with inspection) allow lateral movement between blast radii.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7(8)",
    "cis_rule": "",
    "mitre_technique": "T1021",
    "mitre_tactic": "Lateral Movement",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    vnet := input.virtual_networks[_]
    peerings := object.get(object.get(vnet, "properties", {}), "virtualNetworkPeerings", [])
    count(peerings) > 0
    not subscription_has_firewall
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vnet, "id", ""),
        "resource_type": "Microsoft.Network/virtualNetworks",
        "resource_name": object.get(vnet, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VNet '%s' has %d peering(s) but no Azure Firewall exists in the subscription.", [object.get(vnet, "name", ""), count(peerings)]),
        "evidence": {
            "peering_count": count(peerings)
        },
        "chain_role": metadata.chain_role
    }
}

subscription_has_firewall if {
    r := input.resources[_]
    lower(object.get(r, "type", "")) == "microsoft.network/azurefirewalls"
}
