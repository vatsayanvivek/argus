package argus.azure.zt.data.zt_data_009

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_009",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Data",
    "title": "Key Vault lacks diagnostic settings for secret lifecycle visibility",
    "description": "Without diagnostic settings on a Key Vault, secret-access and expiration events are not captured — near-expiry or overused secrets cannot be detected.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-12",
    "cis_rule": "",
    "mitre_technique": "T1098",
    "mitre_tactic": "Persistence",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    kv := input.key_vaults[_]
    kv_id := object.get(kv, "id", "")
    ds := object.get(input, "diagnostic_settings", {})
    object.get(ds, kv_id, false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": kv_id,
        "resource_type": "Microsoft.KeyVault/vaults",
        "resource_name": object.get(kv, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Key Vault '%s' has no diagnostic settings; secret lifecycle (including expiry) cannot be audited.", [object.get(kv, "name", "")]),
        "evidence": {
            "diagnostic_settings_enabled": false
        },
        "chain_role": metadata.chain_role
    }
}
