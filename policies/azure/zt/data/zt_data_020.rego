package argus.azure.zt.data.zt_data_020

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_020",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "Cognitive Services account allows public network access",
    "description": "Cognitive Services accounts with public network access enabled expose AI/ML endpoints to the internet. Disabling public access and using private endpoints ensures that only trusted networks can invoke inference and training APIs, preventing data exfiltration through model queries.",
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
    r.type == "Microsoft.CognitiveServices/accounts"
    props := object.get(r, "properties", {})
    pna := object.get(props, "publicNetworkAccess", "Enabled")
    pna != "Disabled"
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(r, "id", ""),
        "resource_type": "Microsoft.CognitiveServices/accounts",
        "resource_name": object.get(r, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Cognitive Services account '%s' has publicNetworkAccess='%s' (not Disabled).", [object.get(r, "name", ""), pna]),
        "evidence": {
            "publicNetworkAccess": pna
        },
        "chain_role": metadata.chain_role
    }
}
