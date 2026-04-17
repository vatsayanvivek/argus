package argus.azure.zt.data.zt_data_013

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_013",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Data",
    "title": "Storage account soft delete not enabled for blobs",
    "description": "Storage accounts without blob soft delete cannot recover accidentally or maliciously deleted data. Enabling soft delete provides a retention window during which deleted blobs can be restored, mitigating ransomware and insider threat scenarios.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "CP-9",
    "cis_rule": "",
    "mitre_technique": "T1485",
    "mitre_tactic": "Impact",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    sa := input.storage_accounts[_]
    props := object.get(sa, "properties", {})
    drp := object.get(props, "deleteRetentionPolicy", {})
    object.get(drp, "enabled", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sa, "id", ""),
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": object.get(sa, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Storage account '%s' does not have blob soft delete enabled.", [object.get(sa, "name", "")]),
        "evidence": {
            "deleteRetentionPolicyEnabled": object.get(drp, "enabled", false)
        },
        "chain_role": metadata.chain_role
    }
}
