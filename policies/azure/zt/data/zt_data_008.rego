package argus.azure.zt.data.zt_data_008

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_008",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Data",
    "title": "VM has no backup protection",
    "description": "Virtual machines without Azure Backup / Recovery Services Vault protection cannot be recovered after ransomware or accidental deletion.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "CP-9",
    "cis_rule": "",
    "mitre_technique": "T1485",
    "mitre_tactic": "Impact",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    vm := input.virtual_machines[_]
    not is_backed_up(vm)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vm, "id", ""),
        "resource_type": "Microsoft.Compute/virtualMachines",
        "resource_name": object.get(vm, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VM '%s' has no Recovery Services Vault protection indicator.", [object.get(vm, "name", "")]),
        "evidence": {
            "backup_protected": object.get(vm, "backup_protected", false),
            "tags": object.get(vm, "tags", {})
        },
        "chain_role": metadata.chain_role
    }
}

is_backed_up(vm) if {
    object.get(vm, "backup_protected", false) == true
}

is_backed_up(vm) if {
    tags := object.get(vm, "tags", {})
    object.get(tags, "backup", "") != ""
}
