package argus.azure.zt.data.zt_data_016

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_016",
    "source": "argus-zt",
    "severity": "LOW",
    "pillar": "Data",
    "title": "Storage account blob versioning not enabled",
    "description": "Storage accounts without blob versioning cannot maintain previous versions of objects, making it impossible to recover from accidental overwrites or malicious modifications. Enabling versioning provides an immutable history of blob changes.",
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
    object.get(props, "isBlobVersioningEnabled", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sa, "id", ""),
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": object.get(sa, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Storage account '%s' does not have blob versioning enabled.", [object.get(sa, "name", "")]),
        "evidence": {
            "isBlobVersioningEnabled": object.get(props, "isBlobVersioningEnabled", false)
        },
        "chain_role": metadata.chain_role
    }
}
