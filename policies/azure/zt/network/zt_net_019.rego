package argus.azure.zt.network.zt_net_019

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_019",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Subnet has no Network Security Group associated",
    "description": "Subnets without an associated Network Security Group have no network-level access control, allowing unrestricted traffic flow. Every subnet except dedicated service subnets (GatewaySubnet, AzureFirewallSubnet, AzureBastionSubnet) must have an NSG.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1557",
    "mitre_tactic": "Credential Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

excluded_subnets := {"GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet", "AzureFirewallManagementSubnet", "RouteServerSubnet"}

violation contains msg if {
    subnet := input.subnets[_]
    name := object.get(subnet, "name", "")
    not excluded_subnets[name]
    object.get(subnet, "has_nsg", false) == false
    vnet_name := object.get(subnet, "vnet_name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(subnet, "id", ""),
        "resource_type": "Microsoft.Network/virtualNetworks/subnets",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Subnet '%s' in virtual network '%s' has no NSG associated. All traffic to and from this subnet is unfiltered.", [name, vnet_name]),
        "evidence": {
            "subnet_name": name,
            "vnet_name": vnet_name,
            "has_nsg": false
        },
        "chain_role": metadata.chain_role
    }
}
