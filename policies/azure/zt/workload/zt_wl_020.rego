package argus.azure.zt.workload.zt_wl_020

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_020",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "Virtual Machine disk encryption not enabled",
    "description": "Virtual Machines without OS disk encryption leave data at rest unprotected. An attacker who gains access to the underlying storage or snapshots can read sensitive data directly from the disk without needing OS-level credentials.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "SC-28(1)",
    "cis_rule": "",
    "mitre_technique": "T1005",
    "mitre_tactic": "Collection",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    vm := input.virtual_machines[_]
    props := object.get(vm, "properties", {})
    sp := object.get(props, "storageProfile", {})
    osd := object.get(sp, "osDisk", {})
    not disk_encrypted(osd)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(vm, "id", ""),
        "resource_type": "Microsoft.Compute/virtualMachines",
        "resource_name": object.get(vm, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VM '%s' does not have OS disk encryption enabled.", [object.get(vm, "name", "")]),
        "evidence": {
            "encryptionSettings": object.get(osd, "encryptionSettings", null),
            "diskEncryptionSetId": object.get(object.get(osd, "managedDisk", {}), "diskEncryptionSet", null)
        },
        "chain_role": metadata.chain_role
    }
}

disk_encrypted(osd) if {
    es := object.get(osd, "encryptionSettings", {})
    object.get(es, "enabled", false) == true
}

disk_encrypted(osd) if {
    md := object.get(osd, "managedDisk", {})
    des := object.get(md, "diskEncryptionSet", {})
    object.get(des, "id", "") != ""
}
