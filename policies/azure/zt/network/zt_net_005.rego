package argus.azure.zt.network.zt_net_005

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_005",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Network",
    "title": "No Azure Firewall or NVA deployed",
    "description": "Without a central firewall, outbound traffic cannot be inspected and egress filtering cannot be enforced against command-and-control channels.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7(8)",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    not subscription_has_firewall
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Network/azureFirewalls",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No Azure Firewall resource exists in this subscription; egress cannot be centrally filtered.",
        "evidence": {
            "azure_firewall_count": 0
        },
        "chain_role": metadata.chain_role
    }
}

subscription_has_firewall if {
    r := input.resources[_]
    lower(object.get(r, "type", "")) == "microsoft.network/azurefirewalls"
}
