package argus.azure.zt.identity.zt_id_017

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_017",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Cross-tenant access settings allow inbound trust by default",
    "description": "Default cross-tenant access settings that permit inbound trust allow external tenants to satisfy MFA and device compliance claims, enabling attackers from compromised partner tenants to bypass local Conditional Access controls.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are resources",
    "nist_800_53": "AC-17",
    "cis_rule": "",
    "mitre_technique": "T1199",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    settings := object.get(input, "tenant_settings", {})
    cta := object.get(settings, "cross_tenant_access_default", {})
    inbound := object.get(cta, "inbound_trust", {})
    is_trust_enabled(inbound)
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "Default cross-tenant access settings allow inbound trust, enabling external tenants to satisfy MFA and device compliance claims.",
        "evidence": {
            "cross_tenant_access_default": cta,
            "inbound_trust": inbound
        },
        "chain_role": metadata.chain_role
    }
}

is_trust_enabled(inbound) if {
    object.get(inbound, "isMfaAccepted", false) == true
}

is_trust_enabled(inbound) if {
    object.get(inbound, "isCompliantDeviceAccepted", false) == true
}

is_trust_enabled(inbound) if {
    object.get(inbound, "isHybridAzureADJoinedDeviceAccepted", false) == true
}
