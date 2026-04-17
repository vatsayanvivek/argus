package argus.azure.zt.network.zt_net_011

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_011",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Azure Firewall not deployed in hub virtual network",
    "description": "Azure Firewall provides centralized network traffic filtering and threat intelligence. Without a firewall in the hub network, east-west and north-south traffic flows unfiltered, enabling lateral movement and command-and-control channels.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7(5)",
    "cis_rule": "",
    "mitre_technique": "T1090",
    "mitre_tactic": "Command and Control",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    resources := object.get(input, "resources", [])
    firewalls := [r | r := resources[_]; object.get(r, "type", "") == "Microsoft.Network/azureFirewalls"]
    count(firewalls) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Network/azureFirewalls",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No Azure Firewall resource found in the subscription. Centralized traffic filtering and threat intelligence are unavailable.",
        "evidence": {
            "azure_firewall_count": 0
        },
        "chain_role": metadata.chain_role
    }
}
