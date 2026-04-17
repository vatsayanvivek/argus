package argus.azure.zt.network.zt_net_016

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_016",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "Network Watcher not enabled in all regions",
    "description": "Network Watcher provides network diagnostics, packet capture, and flow logs. If Network Watcher is not deployed in every region where virtual networks exist, blind spots prevent detection of lateral movement and data exfiltration.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-12",
    "cis_rule": "",
    "mitre_technique": "T1562.008",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    vnets := object.get(input, "vnets", [])
    count(vnets) > 0
    vnet_regions := {r | v := vnets[_]; r := lower(object.get(v, "location", ""))}
    resources := object.get(input, "resources", [])
    watchers := [r |
        r := resources[_]
        object.get(r, "type", "") == "Microsoft.Network/networkWatchers"
    ]
    watcher_regions := {lower(object.get(w, "location", "")) | w := watchers[_]}
    missing := vnet_regions - watcher_regions
    count(missing) > 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Network/networkWatchers",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Network Watcher is missing in %d region(s) where virtual networks are deployed: %s.", [count(missing), concat(", ", missing)]),
        "evidence": {
            "vnet_regions": vnet_regions,
            "watcher_regions": watcher_regions,
            "missing_regions": missing
        },
        "chain_role": metadata.chain_role
    }
}
