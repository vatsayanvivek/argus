package argus.azure.zt.identity.zt_id_003

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
    "id": "zt_id_003",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Permanent privileged role assignment without PIM",
    "description": "Privileged roles assigned permanently violate just-in-time principles; PIM eligible assignments reduce standing privilege and blast radius.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy",
    "nist_800_53": "AC-6",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

privileged_keywords := ["Owner", "Contributor", "Administrator"]

# Aggregating rule: emit ONE finding per tenant listing every
# permanent privileged role assignment that has no matching PIM
# eligible assignment. The detail and evidence carry the full count
# and a bounded sample.
violation contains msg if {
    affected := [a |
        a := input.role_assignments[_]
        role_name := object.get(a, "role_name", "")
        some kw in privileged_keywords
        contains(role_name, kw)
        principal_id := object.get(a, "principal_id", "")
        not has_pim_eligible(principal_id, role_name)
    ]
    count(affected) > 0

    sub := object.get(input, "subscription", {})
    tenant_id := object.get(sub, "tenant_id", "unknown")

    sample := [item |
        some i
        i < 25
        a := affected[i]
        item := sprintf("%s:%s", [object.get(a, "role_name", ""), object.get(a, "principal_id", "")])
    ]

    msg := {
        "rule_id": metadata.id,
        "resource_id": sprintf("tenant:%s/permanent-privileged", [tenant_id]),
        "resource_type": "Microsoft.Authorization/roleAssignments",
        "resource_name": "tenant",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("%d permanent privileged role assignment(s) exist with no matching PIM eligible assignment. Standing privilege violates least-access principles.", [count(affected)]),
        "evidence": {
            "affected_count": count(affected),
            "tenant_id": tenant_id,
            "sample_assignments": sample
        },
        "chain_role": metadata.chain_role
    }
}

has_pim_eligible(principal_id, role_name) if {
    pim := input.pim_assignments[_]
    object.get(pim, "principal_id", "") == principal_id
    object.get(pim, "role_name", "") == role_name
    object.get(pim, "assignment_type", "") == "Eligible"
}
