package argus.azure.zt.data.zt_data_006

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_006",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "Storage account encryption-at-rest key source not configured",
    "description": "Storage accounts without an explicit encryption keySource rely on opaque defaults; explicit configuration (Microsoft.Storage or Microsoft.Keyvault) is required for auditability.",
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
    sa := input.storage_accounts[_]
    props := object.get(sa, "properties", {})
    enc := object.get(props, "encryption", {})
    ks := object.get(enc, "keySource", "")
    ks == ""
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sa, "id", ""),
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": object.get(sa, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Storage account '%s' has no encryption.keySource configured.", [object.get(sa, "name", "")]),
        "evidence": {
            "encryption": enc
        },
        "chain_role": metadata.chain_role
    }
}
