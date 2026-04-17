package argus.azure.zt.identity.zt_id_008

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
    "id": "zt_id_008",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Identity",
    "title": "Service Principal holds Owner/Contributor at subscription scope",
    "description": "Service principals with Owner or Contributor rights at subscription scope are high-value credentials whose compromise leads to full tenant control.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "AC-6(1)",
    "cis_rule": "",
    "mitre_technique": "T1078.004",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

privileged_roles := {"Owner", "Contributor"}

is_sub_scope(scope) if {
    contains(scope, "/subscriptions/")
    not contains(scope, "/resourceGroups/")
}

is_sp_priv_at_sub(ra) if {
    object.get(ra, "principal_type", "") == "ServicePrincipal"
    role_name := object.get(ra, "role_name", "")
    privileged_roles[role_name]
    scope := object.get(ra, "scope", "")
    is_sub_scope(scope)
}

violation contains msg if {
    affected := [a | a := input.role_assignments[_]; is_sp_priv_at_sub(a)]
    count(affected) > 0
    sub := object.get(input, "subscription", {})
    sub_id := object.get(sub, "id", "unknown")
    sample := [item |
        some i
        i < 25
        ra := affected[i]
        item := sprintf("%s as %s", [object.get(ra, "principal_id", ""), object.get(ra, "role_name", "")])
    ]
    msg := {
        "rule_id": metadata.id,
        "resource_id": sprintf("%s/privilegedServicePrincipals", [sub_id]),
        "resource_type": "Microsoft.Authorization/roleAssignments",
        "resource_name": "subscription",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("%d service principal(s) hold Owner or Contributor at subscription scope. Compromise of any one yields full subscription control.", [count(affected)]),
        "evidence": {
            "affected_count": count(affected),
            "subscription_id": sub_id,
            "sample_principals": sample
        },
        "chain_role": metadata.chain_role
    }
}
