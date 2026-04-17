package argus.azure.zt.visibility.zt_vis_009

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_009",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Visibility",
    "title": "No Network Watcher in subscription",
    "description": "Network Watcher provides packet capture, flow analytics, and connection troubleshooting; without it, NSG flow logs cannot be processed.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-12",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    not has_network_watcher
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Network/networkWatchers",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No Network Watcher instance found in this subscription.",
        "evidence": {
            "network_watcher_count": 0
        },
        "chain_role": metadata.chain_role
    }
}

has_network_watcher if {
    r := input.resources[_]
    lower(object.get(r, "type", "")) == "microsoft.network/networkwatchers"
}
