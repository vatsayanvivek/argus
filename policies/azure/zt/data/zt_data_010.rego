package argus.azure.zt.data.zt_data_010

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_010",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Data",
    "title": "Storage account not using customer-managed keys (BYOK)",
    "description": "Using Microsoft-managed keys is insufficient for regulated data; customer-managed keys in Key Vault give the tenant control over key rotation and destruction.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured",
    "nist_800_53": "SC-12",
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
    ks := object.get(enc, "keySource", "Microsoft.Storage")
    ks != "Microsoft.Keyvault"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sa, "id", ""),
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": object.get(sa, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Storage account '%s' uses keySource='%s' (not customer-managed key).", [object.get(sa, "name", ""), ks]),
        "evidence": {
            "keySource": ks
        },
        "chain_role": metadata.chain_role
    }
}
