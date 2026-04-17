package argus.azure.zt.visibility.zt_vis_010

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_010",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Visibility",
    "title": "Just-in-Time VM access not configured",
    "description": "JIT VM access enforces time-bound, source-restricted NSG rules for management ports; without it, administrative access paths are always open.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy",
    "nist_800_53": "AC-6",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    count(input.virtual_machines) > 0
    not has_jit_configured
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.Security/jitNetworkAccessPolicies",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Subscription has %d VMs but no Just-in-Time VM access policies configured.", [count(input.virtual_machines)]),
        "evidence": {
            "vm_count": count(input.virtual_machines),
            "jit_policies": 0
        },
        "chain_role": metadata.chain_role
    }
}

has_jit_configured if {
    r := input.resources[_]
    lower(object.get(r, "type", "")) == "microsoft.security/jitnetworkaccesspolicies"
}

has_jit_configured if {
    vm := input.virtual_machines[_]
    object.get(vm, "jit_enabled", false) == true
}
