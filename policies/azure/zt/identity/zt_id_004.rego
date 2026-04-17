package argus.azure.zt.identity.zt_id_004

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_004",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Cross-tenant access unrestricted",
    "description": "Unrestricted cross-tenant access settings allow external tenants to consume resources without scoped B2B policy, enabling supply chain compromise.",
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
    object.get(settings, "cross_tenant_access_unrestricted", false) == true
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "Tenant has cross_tenant_access_unrestricted=true; any external tenant can invoke APIs against this tenant.",
        "evidence": {
            "cross_tenant_access_unrestricted": true
        },
        "chain_role": metadata.chain_role
    }
}
