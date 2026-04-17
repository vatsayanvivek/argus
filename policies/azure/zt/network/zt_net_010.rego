package argus.azure.zt.network.zt_net_010

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_010",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "PaaS resource missing private endpoint",
    "description": "PaaS resources (SQL, Key Vault, Storage) without private endpoints send traffic over the Internet plane; private endpoints are the Zero Trust default.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1530",
    "mitre_tactic": "Collection",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    res := input.sql_servers[_]
    not has_private_endpoint(res)
    msg := build_msg(res, "Microsoft.Sql/servers")
}

violation contains msg if {
    res := input.key_vaults[_]
    not has_private_endpoint(res)
    msg := build_msg(res, "Microsoft.KeyVault/vaults")
}

violation contains msg if {
    res := input.storage_accounts[_]
    not has_private_endpoint(res)
    msg := build_msg(res, "Microsoft.Storage/storageAccounts")
}

has_private_endpoint(res) if {
    props := object.get(res, "properties", {})
    pecs := object.get(props, "privateEndpointConnections", [])
    count(pecs) > 0
}

build_msg(res, rtype) := msg if {
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(res, "id", ""),
        "resource_type": rtype,
        "resource_name": object.get(res, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("%s '%s' has no private endpoint connections.", [rtype, object.get(res, "name", "")]),
        "evidence": {
            "privateEndpointConnections": object.get(object.get(res, "properties", {}), "privateEndpointConnections", [])
        },
        "chain_role": metadata.chain_role
    }
}
