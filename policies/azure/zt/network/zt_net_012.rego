package argus.azure.zt.network.zt_net_012

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_012",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Azure Firewall threat intelligence mode not set to Alert and Deny",
    "description": "Azure Firewall threat intelligence can operate in Off, Alert, or Alert and Deny mode. Only Alert and Deny (Deny) actively blocks connections to known malicious IPs and domains. Alert-only mode logs but does not prevent command-and-control traffic.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7(8)",
    "cis_rule": "",
    "mitre_technique": "T1071",
    "mitre_tactic": "Command and Control",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    res := input.resources[_]
    object.get(res, "type", "") == "Microsoft.Network/azureFirewalls"
    props := object.get(res, "properties", {})
    mode := object.get(props, "threatIntelMode", "Alert")
    mode != "Deny"
    name := object.get(res, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(res, "id", ""),
        "resource_type": "Microsoft.Network/azureFirewalls",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Azure Firewall '%s' has threatIntelMode set to '%s' instead of 'Deny'. Malicious traffic will not be blocked.", [name, mode]),
        "evidence": {
            "firewall_name": name,
            "threatIntelMode": mode,
            "expected": "Deny"
        },
        "chain_role": metadata.chain_role
    }
}
