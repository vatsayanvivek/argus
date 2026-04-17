package argus.azure.zt.data.zt_data_007

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_007",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "SQL Server firewall allows all Azure services",
    "description": "The 0.0.0.0-0.0.0.0 firewall rule opens the SQL server to every subscription on Azure, vastly expanding the blast radius beyond the intended tenant.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    sql := input.sql_servers[_]
    rules := object.get(sql, "firewallRules", [])
    rule := rules[_]
    props := object.get(rule, "properties", rule)
    object.get(props, "startIpAddress", "") == "0.0.0.0"
    object.get(props, "endIpAddress", "") == "0.0.0.0"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sql, "id", ""),
        "resource_type": "Microsoft.Sql/servers/firewallRules",
        "resource_name": object.get(sql, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("SQL server '%s' has 'Allow Azure services' firewall rule '%s' enabled.", [object.get(sql, "name", ""), object.get(rule, "name", "")]),
        "evidence": {
            "rule_name": object.get(rule, "name", ""),
            "startIpAddress": "0.0.0.0",
            "endIpAddress": "0.0.0.0"
        },
        "chain_role": metadata.chain_role
    }
}
