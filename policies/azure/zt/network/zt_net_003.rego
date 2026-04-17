package argus.azure.zt.network.zt_net_003

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_003",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Subnet has no associated Network Security Group",
    "description": "Subnets without an NSG rely entirely on adjacent resource controls; defense-in-depth requires at least one NSG layer on every subnet.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1021",
    "mitre_tactic": "Lateral Movement",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    subnet := input.subnets[_]
    nsg_id := object.get(subnet, "nsg_id", "")
    nsg_id == ""
    not is_gateway_subnet(subnet)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(subnet, "id", ""),
        "resource_type": "Microsoft.Network/virtualNetworks/subnets",
        "resource_name": object.get(subnet, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Subnet '%s' has no NSG associated.", [object.get(subnet, "name", "")]),
        "evidence": {
            "subnet_id": object.get(subnet, "id", ""),
            "nsg_id": nsg_id
        },
        "chain_role": metadata.chain_role
    }
}

is_gateway_subnet(subnet) if {
    object.get(subnet, "name", "") == "GatewaySubnet"
}

is_gateway_subnet(subnet) if {
    object.get(subnet, "name", "") == "AzureFirewallSubnet"
}
