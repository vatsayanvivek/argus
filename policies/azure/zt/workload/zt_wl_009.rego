package argus.azure.zt.workload.zt_wl_009

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
    "id": "zt_wl_009",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "VM missing antimalware extension",
    "description": "Windows VMs should run the Microsoft Antimalware or Defender for Endpoint extension; Linux VMs should run Defender for Servers.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SI-3",
    "cis_rule": "",
    "mitre_technique": "T1059",
    "mitre_tactic": "Execution",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

am_keywords := ["antimalware", "mdeantimalware", "mdatp", "defender"]

violation contains msg if {
    vm := input.virtual_machines[_]
    not has_antimalware(vm)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vm, "id", ""),
        "resource_type": "Microsoft.Compute/virtualMachines",
        "resource_name": object.get(vm, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VM '%s' has no antimalware extension installed.", [object.get(vm, "name", "")]),
        "evidence": {
            "extensions": object.get(vm, "extensions", [])
        },
        "chain_role": metadata.chain_role
    }
}

has_antimalware(vm) if {
    exts := object.get(vm, "extensions", [])
    ext := exts[_]
    name := lower(object.get(ext, "name", ""))
    some kw in am_keywords
    contains(name, kw)
}

has_antimalware(vm) if {
    exts := object.get(vm, "extensions", [])
    ext := exts[_]
    pub := lower(object.get(ext, "publisher", ""))
    contains(pub, "microsoft.azure.security")
    ext_type := lower(object.get(ext, "type", ""))
    contains(ext_type, "antimalware")
}
