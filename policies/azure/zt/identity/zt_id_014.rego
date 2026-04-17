package argus.azure.zt.identity.zt_id_014

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_014",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "No authentication strength policy enforced for administrators",
    "description": "Authentication strength policies ensure administrators use phishing-resistant credentials such as FIDO2 or certificate-based authentication. Without an authentication strength requirement in Conditional Access, admins may authenticate with weaker methods vulnerable to token theft.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "IA-2(6)",
    "cis_rule": "",
    "mitre_technique": "T1556",
    "mitre_tactic": "Credential Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

admin_role_ids := {
    "62e90394-69f5-4237-9190-012177145e10",
    "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
}

targets_admin_role(policy) if {
    conditions := object.get(policy, "conditions", {})
    users := object.get(conditions, "users", {})
    roles := object.get(users, "includeRoles", [])
    roles[_] == admin_role_ids[_]
}

targets_admin_role(policy) if {
    conditions := object.get(policy, "conditions", {})
    users := object.get(conditions, "users", {})
    roles := object.get(users, "includeRoles", [])
    roles[_] == "All"
}

has_auth_strength(policy) if {
    grant := object.get(policy, "grantControls", {})
    auth_strength := object.get(grant, "authenticationStrength", null)
    auth_strength != null
}

violation contains msg if {
    policies := object.get(input, "conditional_access_policies", [])
    admin_policies := [p | p := policies[_]; targets_admin_role(p)]
    admin_policies_with_strength := [p | p := admin_policies[_]; has_auth_strength(p)]
    count(admin_policies_with_strength) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccessPolicies",
        "resource_name": "tenant",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("No Conditional Access policy enforces authentication strength for administrator roles (%d admin-targeting policies found, none with authenticationStrength).", [count(admin_policies)]),
        "evidence": {
            "admin_targeting_policies": count(admin_policies),
            "policies_with_auth_strength": 0
        },
        "chain_role": metadata.chain_role
    }
}
