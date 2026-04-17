package argus.azure.zt.visibility.zt_vis_005

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_005",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Visibility",
    "title": "Activity log retention appears insufficient",
    "description": "A very small activity log sample (<100 events) suggests short retention or limited ingestion; compliance frameworks require 90+ days of activity history.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-11",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    log := object.get(input, "activity_log", [])
    count(log) < 100
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Insights/logProfiles",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Activity log snapshot contains only %d events; retention or ingestion may be insufficient (target: 90+ days).", [count(log)]),
        "evidence": {
            "event_count": count(log)
        },
        "chain_role": metadata.chain_role
    }
}
