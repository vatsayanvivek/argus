package argus.azure.zt.data.zt_data_014

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_014",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "Key Vault does not have purge protection enabled",
    "description": "Key Vaults without purge protection allow permanently deleted keys, secrets, and certificates to be irrecoverably lost immediately. Enabling purge protection enforces a mandatory retention period, preventing malicious or accidental permanent deletion of cryptographic material.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "SC-12",
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
        "detail": sprintf("Key Vault '%s' does not have purge protection enabled.", [object.get(kv, "name", "")]),
        "evidence": {
            "enablePurgeProtection": object.get(props, "enablePurgeProtection", false)
        },
        "chain_role": metadata.chain_role
    }
}
