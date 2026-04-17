package argus.azure.zt.identity.zt_id_009

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_009",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "External collaboration unrestricted",
    "description": "Unrestricted guest permissions or invite settings allow external identities to enumerate directory objects and potentially escalate via consent attacks.",
    "zt_tenet": "Tenet 4",
    "nist_800_207": "Tenet 4 - Access determined by dynamic policy",
    "nist_800_53": "AC-3",
    "cis_rule": "",
    "mitre_technique": "T1199",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    settings := object.get(input, "tenant_settings", {})
    is_unrestricted(settings)
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Guest user permissions='%s' and invite restrictions='%s' permit unrestricted external collaboration.", [object.get(settings, "guest_user_permissions", ""), object.get(settings, "guest_invite_restrictions", "")]),
        "evidence": {
            "guest_user_permissions": object.get(settings, "guest_user_permissions", ""),
            "guest_invite_restrictions": object.get(settings, "guest_invite_restrictions", "")
        },
        "chain_role": metadata.chain_role
    }
}

is_unrestricted(settings) if {
    object.get(settings, "guest_user_permissions", "") == "FullAccess"
}

is_unrestricted(settings) if {
    object.get(settings, "guest_invite_restrictions", "") == "everyone"
}
