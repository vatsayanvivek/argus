package argus.azure.zt.identity.zt_id_005

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_005",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Legacy authentication protocols enabled",
    "description": "Legacy auth (IMAP/POP/SMTP/ActiveSync) bypasses modern controls including MFA and conditional access, enabling password spray attacks.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured",
    "nist_800_53": "IA-2",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    settings := object.get(input, "tenant_settings", {})
    object.get(settings, "legacy_auth_enabled", false) == true
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "Legacy authentication protocols are enabled; these bypass MFA and conditional access policies.",
        "evidence": {
            "legacy_auth_enabled": true
        },
        "chain_role": metadata.chain_role
    }
}
