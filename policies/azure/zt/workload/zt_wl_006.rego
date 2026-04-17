package argus.azure.zt.workload.zt_wl_006

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_006",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "VM missing vulnerability assessment extension",
    "description": "VMs without the Qualys or Defender vulnerability assessment extension have no visibility into unpatched CVEs and known vulnerable software.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "RA-5",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

va_publishers := {"Qualys", "Microsoft.Azure.Security", "Microsoft.Azure.Security.Monitoring"}

violation contains msg if {
    vm := input.virtual_machines[_]
    not has_va_extension(vm)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vm, "id", ""),
        "resource_type": "Microsoft.Compute/virtualMachines",
        "resource_name": object.get(vm, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VM '%s' has no vulnerability assessment extension installed.", [object.get(vm, "name", "")]),
        "evidence": {
            "extensions": object.get(vm, "extensions", [])
        },
        "chain_role": metadata.chain_role
    }
}

has_va_extension(vm) if {
    exts := object.get(vm, "extensions", [])
    ext := exts[_]
    pub := object.get(ext, "publisher", "")
    va_publishers[pub]
    name := object.get(ext, "name", "")
    contains(lower(name), "vulnerability")
}

has_va_extension(vm) if {
    exts := object.get(vm, "extensions", [])
    ext := exts[_]
    contains(lower(object.get(ext, "name", "")), "vulnerabilityassessment")
}
