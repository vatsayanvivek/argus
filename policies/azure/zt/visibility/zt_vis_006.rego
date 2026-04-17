package argus.azure.zt.visibility.zt_vis_006

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_006",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Visibility",
    "title": "NSG flow logs disabled",
    "description": "NSG flow logs are the only network-level record of allowed and denied traffic; without them, lateral movement investigations are impossible.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "AU-12",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    nsg := input.network_security_groups[_]
    object.get(nsg, "flow_logs_enabled", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(nsg, "id", ""),
        "resource_type": "Microsoft.Network/networkSecurityGroups",
        "resource_name": object.get(nsg, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("NSG '%s' does not have flow logs enabled.", [object.get(nsg, "name", "")]),
        "evidence": {
            "flow_logs_enabled": object.get(nsg, "flow_logs_enabled", false)
        },
        "chain_role": metadata.chain_role
    }
}
