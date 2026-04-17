package argus.azure.zt.identity.zt_id_010

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_010",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "No access reviews configured",
    "description": "Without periodic access reviews, stale privileged access accumulates and the principle of least privilege erodes over time.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy",
    "nist_800_53": "AC-2(7)",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Persistence",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    reviews := object.get(input, "access_reviews", [])
    count(reviews) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/accessReviews",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No access reviews are configured at the subscription/tenant level.",
        "evidence": {
            "access_review_count": 0
        },
        "chain_role": metadata.chain_role
    }
}
