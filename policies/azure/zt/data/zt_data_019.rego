package argus.azure.zt.data.zt_data_019

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_019",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "Service Bus namespace allows public network access",
    "description": "Service Bus namespaces with public network access enabled are reachable from the internet, allowing any authenticated or unauthenticated caller to attempt connections. Disabling public access and using private endpoints restricts the attack surface to trusted networks.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Monitor and measure integrity and security posture of assets",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1530",
    "mitre_tactic": "Collection",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    r := input.resources[_]
    r.type == "Microsoft.ServiceBus/namespaces"
    props := object.get(r, "properties", {})
    pna := object.get(props, "publicNetworkAccess", "Enabled")
    pna != "Disabled"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(r, "id", ""),
        "resource_type": "Microsoft.ServiceBus/namespaces",
        "resource_name": object.get(r, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Service Bus namespace '%s' has publicNetworkAccess='%s' (not Disabled).", [object.get(r, "name", ""), pna]),
        "evidence": {
            "publicNetworkAccess": pna
        },
        "chain_role": metadata.chain_role
    }
}
