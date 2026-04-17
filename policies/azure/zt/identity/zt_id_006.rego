package argus.azure.zt.identity.zt_id_006

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_006",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Identity",
    "title": "No enabled conditional access policies",
    "description": "Without enabled conditional access, authentication decisions rely solely on credentials. Dynamic policy is foundational to Zero Trust.",
    "zt_tenet": "Tenet 4",
    "nist_800_207": "Tenet 4 - Access determined by dynamic policy",
    "nist_800_53": "AC-3",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    policies := object.get(input, "conditional_access_policies", [])
    not has_enabled_policy(policies)
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccess",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("No enabled conditional access policies found in tenant (total=%d).", [count(policies)]),
        "evidence": {
            "policy_count": count(policies)
        },
        "chain_role": metadata.chain_role
    }
}

has_enabled_policy(policies) if {
    p := policies[_]
    object.get(p, "state", "") == "enabled"
}
