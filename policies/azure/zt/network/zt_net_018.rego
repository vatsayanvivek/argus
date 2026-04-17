package argus.azure.zt.network.zt_net_018

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_018",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "NSG allows all outbound traffic to the Internet",
    "description": "Network Security Groups that permit unrestricted outbound traffic to the Internet enable data exfiltration and command-and-control communication. Outbound traffic should be restricted to known destinations and ports.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1048",
    "mitre_tactic": "Exfiltration",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

is_allow_all_outbound(rule) if {
    object.get(rule, "direction", "") == "Outbound"
    object.get(rule, "access", "") == "Allow"
    dst := object.get(rule, "destinationAddressPrefix", "")
    dst == "*"
    port := object.get(rule, "destinationPortRange", "")
    port == "*"
}

violation contains msg if {
    nsg := input.network_security_groups[_]
    rules := object.get(nsg, "security_rules", [])
    rule := rules[_]
    is_allow_all_outbound(rule)
    name := object.get(nsg, "name", "unknown")
    rule_name := object.get(rule, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(nsg, "id", ""),
        "resource_type": "Microsoft.Network/networkSecurityGroups",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("NSG '%s' rule '%s' allows all outbound traffic (destination: *, port: *) to the Internet, enabling data exfiltration.", [name, rule_name]),
        "evidence": {
            "nsg_name": name,
            "rule_name": rule_name,
            "direction": "Outbound",
            "access": "Allow",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "*"
        },
        "chain_role": metadata.chain_role
    }
}
