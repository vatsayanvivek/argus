package argus.azure.zt.data.zt_data_005

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_005",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Data",
    "title": "Key Vault purge protection disabled",
    "description": "Without purge protection, a soft-deleted vault can be permanently destroyed within the retention window; this defeats the purpose of soft delete for recovery.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "CP-9",
    "cis_rule": "",
    "mitre_technique": "T1485",
    "mitre_tactic": "Impact",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    kv := input.key_vaults[_]
    props := object.get(kv, "properties", {})
    object.get(props, "enablePurgeProtection", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(kv, "id", ""),
        "resource_type": "Microsoft.KeyVault/vaults",
        "resource_name": object.get(kv, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Key Vault '%s' has purge protection disabled.", [object.get(kv, "name", "")]),
        "evidence": {
            "enablePurgeProtection": object.get(props, "enablePurgeProtection", false)
        },
        "chain_role": metadata.chain_role
    }
}
