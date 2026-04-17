package argus.azure.zt.identity.zt_id_019

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_019",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "Token lifetime exceeds secure threshold",
    "description": "Access token lifetimes exceeding 60 minutes widen the window for token theft and replay attacks. Shorter lifetimes force re-evaluation of Conditional Access policies and reduce exposure from compromised tokens.",
    "zt_tenet": "Tenet 3",
    "nist_800_207": "Tenet 3 - Access granted on a per-session basis",
    "nist_800_53": "AC-12",
    "cis_rule": "",
    "mitre_technique": "T1550.001",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    settings := object.get(input, "tenant_settings", {})
    lifetime := object.get(settings, "token_lifetime_minutes", 60)
    lifetime > 60
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Token lifetime is set to %d minutes, exceeding the recommended 60-minute threshold. Extended lifetimes increase token replay risk.", [lifetime]),
        "evidence": {
            "token_lifetime_minutes": lifetime,
            "recommended_max": 60
        },
        "chain_role": metadata.chain_role
    }
}
