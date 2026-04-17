package argus.azure.zt.visibility.zt_vis_002

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_002",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Visibility",
    "title": "No Log Analytics workspace in subscription",
    "description": "Without a Log Analytics workspace, diagnostic logs have nowhere to be stored or queried; SIEM and detection pipelines cannot function.",
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
    not has_workspace
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.OperationalInsights/workspaces",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No Log Analytics workspace exists in this subscription.",
        "evidence": {
            "workspace_count": 0
        },
        "chain_role": metadata.chain_role
    }
}

has_workspace if {
    r := input.resources[_]
    lower(object.get(r, "type", "")) == "microsoft.operationalinsights/workspaces"
}
