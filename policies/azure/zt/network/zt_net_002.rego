package argus.azure.zt.network.zt_net_002

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_002",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Network",
    "title": "NSG allows RDP (3389) from the Internet",
    "description": "Exposing RDP to the Internet is a top initial access vector; BlueKeep and brute force against exposed RDP remain widely exploited.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

internet_sources := {"*", "0.0.0.0/0", "Internet"}

violation contains msg if {
    nsg := input.network_security_groups[_]
    rules := object.get(object.get(nsg, "properties", {}), "securityRules", [])
    rule := rules[_]
    props := object.get(rule, "properties", rule)
    object.get(props, "direction", "") == "Inbound"
    object.get(props, "access", "") == "Allow"
    port_matches(props, "3389")
    src := object.get(props, "sourceAddressPrefix", "")
    internet_sources[src]
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(nsg, "id", ""),
        "resource_type": "Microsoft.Network/networkSecurityGroups",
        "resource_name": object.get(nsg, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("NSG '%s' rule '%s' allows inbound RDP from %s.", [object.get(nsg, "name", ""), object.get(rule, "name", ""), src]),
        "evidence": {
            "rule_name": object.get(rule, "name", ""),
            "source": src,
            "destinationPortRange": object.get(props, "destinationPortRange", "")
        },
        "chain_role": metadata.chain_role
    }
}

port_matches(props, p) if {
    object.get(props, "destinationPortRange", "") == p
}

port_matches(props, p) if {
    object.get(props, "destinationPortRange", "") == "*"
}

port_matches(props, p) if {
    ranges := object.get(props, "destinationPortRanges", [])
    ranges[_] == p
}

port_matches(props, p) if {
    ranges := object.get(props, "destinationPortRanges", [])
    ranges[_] == "*"
}
