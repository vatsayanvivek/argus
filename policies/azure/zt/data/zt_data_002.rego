package argus.azure.zt.data.zt_data_002

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_002",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "SQL Server Transparent Data Encryption (TDE) disabled",
    "description": "SQL databases without TDE leave data files unencrypted at rest; physical or backup exfiltration yields plaintext data.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured",
    "nist_800_53": "SC-28",
    "cis_rule": "",
    "mitre_technique": "T1486",
    "mitre_tactic": "Impact",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    sql := input.sql_servers[_]
    dbs := object.get(sql, "databases", [])
    db := dbs[_]
    tde := object.get(db, "transparentDataEncryption", {})
    status := object.get(tde, "status", object.get(tde, "state", ""))
    status != "Enabled"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(db, "id", object.get(sql, "id", "")),
        "resource_type": "Microsoft.Sql/servers/databases",
        "resource_name": sprintf("%s/%s", [object.get(sql, "name", ""), object.get(db, "name", "")]),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("SQL database '%s' on server '%s' has TDE status '%s'.", [object.get(db, "name", ""), object.get(sql, "name", ""), status]),
        "evidence": {
            "tde_status": status
        },
        "chain_role": metadata.chain_role
    }
}
