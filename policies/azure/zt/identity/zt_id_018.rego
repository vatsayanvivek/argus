package argus.azure.zt.identity.zt_id_018

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_018",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Identity Protection sign-in risk policy not enabled",
    "description": "Sign-in risk policies in Identity Protection evaluate real-time signals such as atypical travel, anonymous IP, and password spray patterns. Without a Conditional Access policy referencing sign-in risk levels, compromised sessions go undetected.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured regardless of network location",
    "nist_800_53": "SI-4",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

has_signin_risk(policy) if {
    conditions := object.get(policy, "conditions", {})
    risk_levels := object.get(conditions, "signInRiskLevels", [])
    count(risk_levels) > 0
}

violation contains msg if {
    policies := object.get(input, "conditional_access_policies", [])
    policies_with_risk := [p | p := policies[_]; has_signin_risk(p)]
    count(policies_with_risk) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccessPolicies",
        "resource_name": "tenant",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("No Conditional Access policy evaluates sign-in risk levels (%d policies examined). Compromised sign-ins will not trigger adaptive controls.", [count(policies)]),
        "evidence": {
            "total_policies": count(policies),
            "policies_with_signin_risk": 0
        },
        "chain_role": metadata.chain_role
    }
}
