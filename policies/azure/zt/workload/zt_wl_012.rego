package argus.azure.zt.workload.zt_wl_012

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_012",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "Container Registry has admin account enabled",
    "description": "Container Registries with the admin account enabled expose a shared credential pair that cannot be scoped or audited per-principal. Disabling the admin account and using Azure AD tokens or managed identities enforces least-privilege and individual accountability.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Authentication and authorization are dynamic and strictly enforced",
    "nist_800_53": "AC-6",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    r := input.resources[_]
    r.type == "Microsoft.ContainerRegistry/registries"
    props := object.get(r, "properties", {})
    object.get(props, "adminUserEnabled", false) == true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(r, "id", ""),
        "resource_type": "Microsoft.ContainerRegistry/registries",
        "resource_name": object.get(r, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Container Registry '%s' has the admin account enabled, allowing shared credential access.", [object.get(r, "name", "")]),
        "evidence": {
            "adminUserEnabled": true
        },
        "chain_role": metadata.chain_role
    }
}
