package argus.azure.zt.data.zt_data_003

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_003",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "SQL Server auditing not enabled",
    "description": "Without SQL auditing, data access patterns are invisible; exfiltration and unauthorized reads cannot be detected or reconstructed.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-2",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    sql := input.sql_servers[_]
    audit := object.get(sql, "auditingSettings", {})
    object.get(audit, "state", "Disabled") != "Enabled"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sql, "id", ""),
        "resource_type": "Microsoft.Sql/servers",
        "resource_name": object.get(sql, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("SQL server '%s' has auditingSettings.state != Enabled.", [object.get(sql, "name", "")]),
        "evidence": {
            "auditingSettings_state": object.get(audit, "state", "Disabled")
        },
        "chain_role": metadata.chain_role
    }
}
