package argus.azure.zt.visibility.zt_vis_004

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
    "id": "zt_vis_004",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Visibility",
    "title": "No alerting on critical management operations",
    "description": "The activity log shows no recent role or policy assignment events; either nothing is happening (suspicious) or alerting pipelines are disconnected.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-6",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

critical_ops := ["Microsoft.Authorization/roleAssignments", "Microsoft.Authorization/policyAssignments"]

violation contains msg if {
    not has_critical_events
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Insights/activityLogAlerts",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "Activity log has no role assignment or policy assignment events captured; alerting on critical operations is absent.",
        "evidence": {
            "critical_events_seen": 0
        },
        "chain_role": metadata.chain_role
    }
}

has_critical_events if {
    log := object.get(input, "activity_log", [])
    evt := log[_]
    op := object.get(evt, "operationName", "")
    some critical in critical_ops
    contains(op, critical)
}
