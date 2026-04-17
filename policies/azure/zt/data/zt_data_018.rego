package argus.azure.zt.data.zt_data_018

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_018",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Data",
    "title": "Event Hub namespace does not use customer-managed key encryption",
    "description": "Event Hub namespaces without customer-managed key encryption rely on Microsoft-managed keys, limiting tenant control over the encryption lifecycle. Using Key Vault-backed keys ensures the organization can rotate, revoke, and audit access to the encryption material.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "SC-28(1)",
    "cis_rule": "",
    "mitre_technique": "T1530",
    "mitre_tactic": "Collection",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    r := input.resources[_]
    r.type == "Microsoft.EventHub/namespaces"
    props := object.get(r, "properties", {})
    enc := object.get(props, "encryption", {})
    ks := object.get(enc, "keySource", "Microsoft.EventHub")
    ks != "Microsoft.KeyVault"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(r, "id", ""),
        "resource_type": "Microsoft.EventHub/namespaces",
        "resource_name": object.get(r, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Event Hub namespace '%s' uses keySource='%s' (not customer-managed key).", [object.get(r, "name", ""), ks]),
        "evidence": {
            "keySource": ks
        },
        "chain_role": metadata.chain_role
    }
}
