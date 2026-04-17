package argus.azure.zt.network.zt_net_009

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_009",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Storage account network default action is Allow",
    "description": "Storage accounts with defaultAction=Allow are reachable from any source on the Internet; network ACLs must deny by default.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1530",
    "mitre_tactic": "Collection",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    sa := input.storage_accounts[_]
    props := object.get(sa, "properties", {})
    acls := object.get(props, "networkAcls", {})
    object.get(acls, "defaultAction", "Allow") == "Allow"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sa, "id", ""),
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": object.get(sa, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Storage account '%s' has networkAcls.defaultAction=Allow.", [object.get(sa, "name", "")]),
        "evidence": {
            "defaultAction": object.get(acls, "defaultAction", "Allow"),
            "bypass": object.get(acls, "bypass", "")
        },
        "chain_role": metadata.chain_role
    }
}
