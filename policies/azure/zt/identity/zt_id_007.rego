package argus.azure.zt.identity.zt_id_007

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_007",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "No PIM assignments configured",
    "description": "Absence of Privileged Identity Management (PIM) indicates that privileged roles are standing rather than just-in-time; this violates least-privilege principles.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy",
    "nist_800_53": "AC-6",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    pim := object.get(input, "pim_assignments", [])
    count(pim) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Authorization/pim",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No PIM (Privileged Identity Management) assignments exist; all privileged access appears to be standing.",
        "evidence": {
            "pim_assignment_count": 0
        },
        "chain_role": metadata.chain_role
    }
}
