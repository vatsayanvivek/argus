package argus.azure.zt.identity.zt_id_021

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_021",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "PIM role activation lacks approval workflow",
    "description": "Privileged Identity Management role assignments for highly privileged roles should require an approval workflow. Without approval, a compromised account can self-activate Global Administrator or equivalent roles instantly.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "AC-6(1)",
    "cis_rule": "",
    "mitre_technique": "T1078.004",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

privileged_roles := {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Security Administrator",
    "Application Administrator"
}

violation contains msg if {
    assignment := input.pim_assignments[_]
    role_name := object.get(assignment, "role_name", "")
    privileged_roles[role_name]
    object.get(assignment, "approval_required", false) == false
    principal := object.get(assignment, "principal_display_name", object.get(assignment, "principal_id", "unknown"))
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(assignment, "id", ""),
        "resource_type": "Microsoft.Authorization/roleEligibilitySchedules",
        "resource_name": principal,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("PIM eligible assignment for '%s' role (principal: %s) does not require approval. Self-activation of privileged roles enables immediate escalation.", [role_name, principal]),
        "evidence": {
            "role_name": role_name,
            "principal": principal,
            "approval_required": false
        },
        "chain_role": metadata.chain_role
    }
}
