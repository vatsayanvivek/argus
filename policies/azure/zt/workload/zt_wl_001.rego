package argus.azure.zt.workload.zt_wl_001

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_001",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "Virtual Machine has no managed identity",
    "description": "VMs without a system or user-assigned managed identity must store credentials locally, creating credential sprawl and privilege escalation opportunities.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured",
    "nist_800_53": "IA-5",
    "cis_rule": "",
    "mitre_technique": "T1552",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    vm := input.virtual_machines[_]
    not has_identity(vm)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vm, "id", ""),
        "resource_type": "Microsoft.Compute/virtualMachines",
        "resource_name": object.get(vm, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VM '%s' has no managed identity assigned.", [object.get(vm, "name", "")]),
        "evidence": {
            "identity": object.get(vm, "identity", null)
        },
        "chain_role": metadata.chain_role
    }
}

has_identity(vm) if {
    ident := object.get(vm, "identity", null)
    ident != null
    object.get(ident, "type", "None") != "None"
}
