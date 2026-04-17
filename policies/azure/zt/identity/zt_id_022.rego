package argus.azure.zt.identity.zt_id_022

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_022",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "User risk policy not enabled in Identity Protection",
    "description": "User risk policies detect compromised accounts by analyzing signals such as leaked credentials and impossible travel. Without a Conditional Access policy evaluating user risk levels, compromised identities remain active indefinitely.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured regardless of network location",
    "nist_800_53": "SI-4",
    "cis_rule": "",
    "mitre_technique": "T1110",
    "mitre_tactic": "Credential Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

has_user_risk(policy) if {
    conditions := object.get(policy, "conditions", {})
    risk_levels := object.get(conditions, "userRiskLevels", [])
    count(risk_levels) > 0
}

violation contains msg if {
    policies := object.get(input, "conditional_access_policies", [])
    policies_with_risk := [p | p := policies[_]; has_user_risk(p)]
    count(policies_with_risk) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccessPolicies",
        "resource_name": "tenant",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("No Conditional Access policy evaluates user risk levels (%d policies examined). Compromised identities will not be remediated automatically.", [count(policies)]),
        "evidence": {
            "total_policies": count(policies),
            "policies_with_user_risk": 0
        },
        "chain_role": metadata.chain_role
    }
}
