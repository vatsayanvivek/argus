package argus.azure.zt.data.zt_data_015

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_015",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Data",
    "title": "SQL Database TDE uses service-managed key instead of customer-managed",
    "description": "SQL Servers using service-managed keys for Transparent Data Encryption delegate key lifecycle control to Microsoft. Customer-managed keys in Azure Key Vault provide full control over key rotation, revocation, and destruction, meeting regulatory requirements for data sovereignty.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "SC-28(1)",
    "cis_rule": "",
    "mitre_technique": "T1486",
    "mitre_tactic": "Impact",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    srv := input.sql_servers[_]
    props := object.get(srv, "properties", {})
    ep := object.get(props, "encryptionProtector", {})
    skt := object.get(ep, "serverKeyType", "ServiceManaged")
    skt == "ServiceManaged"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(srv, "id", ""),
        "resource_type": "Microsoft.Sql/servers",
        "resource_name": object.get(srv, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("SQL Server '%s' TDE uses service-managed key instead of customer-managed key.", [object.get(srv, "name", "")]),
        "evidence": {
            "serverKeyType": skt
        },
        "chain_role": metadata.chain_role
    }
}
