package argus.azure.zt.identity.zt_id_023

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_023",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "MFA registration policy not enforced for all users",
    "description": "Without a Conditional Access policy requiring MFA registration for all users, new or existing accounts may operate without multi-factor authentication, creating an entry point for password-based attacks.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "IA-2(1)",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

targets_all_users(policy) if {
    conditions := object.get(policy, "conditions", {})
    users := object.get(conditions, "users", {})
    include := object.get(users, "includeUsers", [])
    include[_] == "All"
}

requires_mfa(policy) if {
    grant := object.get(policy, "grantControls", {})
    controls := object.get(grant, "builtInControls", [])
    controls[_] == "mfa"
}

violation contains msg if {
    policies := object.get(input, "conditional_access_policies", [])
    mfa_all := [p |
        p := policies[_]
        targets_all_users(p)
        requires_mfa(p)
    ]
    count(mfa_all) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccessPolicies",
        "resource_name": "tenant",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("No Conditional Access policy requires MFA for all users (%d policies examined). Users may operate without multi-factor authentication.", [count(policies)]),
        "evidence": {
            "total_policies": count(policies),
            "policies_requiring_mfa_for_all": 0
        },
        "chain_role": metadata.chain_role
    }
}
