package argus.azure.zt.data.zt_data_004

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_004",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Data",
    "title": "Key Vault soft delete disabled",
    "description": "Key Vaults without soft delete are vulnerable to accidental or malicious permanent deletion, destroying keys and secrets that protect downstream resources.",
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
    object.get(props, "enableSoftDelete", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(kv, "id", ""),
        "resource_type": "Microsoft.KeyVault/vaults",
        "resource_name": object.get(kv, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Key Vault '%s' has soft delete disabled.", [object.get(kv, "name", "")]),
        "evidence": {
            "enableSoftDelete": object.get(props, "enableSoftDelete", false)
        },
        "chain_role": metadata.chain_role
    }
}
