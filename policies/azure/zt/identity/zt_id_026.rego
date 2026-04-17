package argus.azure.zt.identity.zt_id_026

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_026",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "No access reviews configured for privileged roles",
    "description": "Without periodic access reviews on privileged directory roles, stale or unnecessary role assignments accumulate over time, expanding the blast radius of credential compromise and violating least-privilege principles.",
    "zt_tenet": "Tenet 4",
    "nist_800_207": "Tenet 4 - Access to resources is determined by dynamic policy",
    "nist_800_53": "AC-2",
    "cis_rule": "",
    "mitre_technique": "T1078.004",
    "mitre_tactic": "Persistence",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    tenant := object.get(input, "tenant_settings", {})
    reviews := object.get(input, "access_reviews", [])
    count(reviews) == 0
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(tenant, "tenant_id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(tenant, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No access reviews are configured for privileged directory roles. Stale role assignments accumulate without periodic review, violating least-privilege.",
        "evidence": {
            "access_review_count": 0
        },
        "chain_role": metadata.chain_role
    }
}
