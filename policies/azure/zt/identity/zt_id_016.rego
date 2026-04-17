package argus.azure.zt.identity.zt_id_016

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_016",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Guest users have excessive directory permissions",
    "description": "Guest users with assigned directory roles violate least-privilege principles. External identities should access resources through scoped entitlements, not broad directory roles that enable lateral movement and privilege escalation.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "AC-6",
    "cis_rule": "",
    "mitre_technique": "T1078.004",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    user := input.users[_]
    object.get(user, "user_type", "") == "Guest"
    roles := object.get(user, "assigned_roles", [])
    count(roles) > 0
    display_name := object.get(user, "display_name", object.get(user, "user_principal_name", "unknown"))
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(user, "id", ""),
        "resource_type": "Microsoft.Graph/users",
        "resource_name": display_name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Guest user '%s' has %d directory role(s) assigned. Guest accounts should not hold directory roles.", [display_name, count(roles)]),
        "evidence": {
            "user_principal_name": object.get(user, "user_principal_name", ""),
            "user_type": "Guest",
            "assigned_roles": roles
        },
        "chain_role": metadata.chain_role
    }
}
