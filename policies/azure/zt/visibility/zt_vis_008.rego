package argus.azure.zt.visibility.zt_vis_008

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_008",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Visibility",
    "title": "No alert on Owner role assignment",
    "description": "Owner role grants are the highest-privilege change an attacker makes during escalation; activity log shows no owner-role events, indicating no alerting on this operation.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-6",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    not has_owner_events
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Insights/activityLogAlerts",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "Activity log contains no role assignment events referencing 'Owner'; no alerting appears to be in place for owner grants.",
        "evidence": {
            "owner_events_seen": 0
        },
        "chain_role": metadata.chain_role
    }
}

has_owner_events if {
    log := object.get(input, "activity_log", [])
    evt := log[_]
    op := lower(object.get(evt, "operationName", ""))
    contains(op, "roleassignments")
    props := object.get(evt, "properties", {})
    contains(lower(sprintf("%v", [props])), "owner")
}
