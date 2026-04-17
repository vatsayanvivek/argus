package argus.azure.zt.identity.zt_id_020

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_020",
    "source": "argus-zt",
    "severity": "LOW",
    "pillar": "Identity",
    "title": "Administrative units not used for role scoping",
    "description": "Administrative units allow scoping directory role assignments to specific subsets of users, groups, or devices. Without administrative units, all role assignments are tenant-wide, violating least-privilege principles.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "AC-6(2)",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    settings := object.get(input, "tenant_settings", {})
    au_count := object.get(settings, "admin_units_count", 0)
    au_count == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No administrative units are configured. All directory role assignments are tenant-wide, preventing granular role scoping.",
        "evidence": {
            "admin_units_count": 0
        },
        "chain_role": metadata.chain_role
    }
}
