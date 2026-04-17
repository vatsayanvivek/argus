package argus.azure.zt.data.zt_data_011

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_011",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "Cosmos DB account allows access from all networks",
    "description": "Cosmos DB accounts without virtual network filtering or with public network access enabled are reachable from any network. Restricting access to specific VNets or disabling public access limits the blast radius of credential compromise.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "AC-3",
    "cis_rule": "",
    "mitre_technique": "T1530",
    "mitre_tactic": "Collection",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    r := input.resources[_]
    r.type == "Microsoft.DocumentDB/databaseAccounts"
    props := object.get(r, "properties", {})
    object.get(props, "isVirtualNetworkFilterEnabled", false) != true
    object.get(props, "publicNetworkAccess", "Enabled") != "Disabled"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(r, "id", ""),
        "resource_type": "Microsoft.DocumentDB/databaseAccounts",
        "resource_name": object.get(r, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Cosmos DB account '%s' allows access from all networks (VNet filter disabled, public access not disabled).", [object.get(r, "name", "")]),
        "evidence": {
            "isVirtualNetworkFilterEnabled": object.get(props, "isVirtualNetworkFilterEnabled", false),
            "publicNetworkAccess": object.get(props, "publicNetworkAccess", "Enabled")
        },
        "chain_role": metadata.chain_role
    }
}
