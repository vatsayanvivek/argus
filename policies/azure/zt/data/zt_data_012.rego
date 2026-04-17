package argus.azure.zt.data.zt_data_012

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_012",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "SQL Server auditing not enabled",
    "description": "SQL Servers without auditing enabled lack visibility into database operations, making it impossible to detect unauthorized access, data exfiltration, or tampering. Enabling auditing ensures all queries and administrative actions are logged for forensic analysis.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Monitor and measure integrity and security posture of assets",
    "nist_800_53": "AU-12",
    "cis_rule": "",
    "mitre_technique": "T1565",
    "mitre_tactic": "Impact",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    srv := input.sql_servers[_]
    props := object.get(srv, "properties", {})
    ap := object.get(props, "auditingPolicy", {})
    object.get(ap, "state", "Disabled") != "Enabled"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(srv, "id", ""),
        "resource_type": "Microsoft.Sql/servers",
        "resource_name": object.get(srv, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("SQL Server '%s' does not have auditing enabled.", [object.get(srv, "name", "")]),
        "evidence": {
            "auditingPolicyState": object.get(ap, "state", "Disabled")
        },
        "chain_role": metadata.chain_role
    }
}
