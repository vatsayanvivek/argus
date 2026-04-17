package argus.azure.zt.data.zt_data_017

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_017",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Data",
    "title": "Critical resources have no Azure Backup configured",
    "description": "Virtual machines and SQL servers without associated Azure Backup vault protection are vulnerable to permanent data loss from ransomware, accidental deletion, or destructive attacks. Configuring backup ensures recoverability within defined RPO/RTO targets.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All data sources and computing services are considered resources",
    "nist_800_53": "CP-9",
    "cis_rule": "",
    "mitre_technique": "T1486",
    "mitre_tactic": "Impact",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

# Collect all resource IDs that have backup protection
backup_protected_ids[rid] if {
    r := input.resources[_]
    r.type == "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems"
    props := object.get(r, "properties", {})
    rid := object.get(props, "sourceResourceId", "")
    rid != ""
}

# VMs without backup
violation contains msg if {
    vm := input.virtual_machines[_]
    vm_id := object.get(vm, "id", "")
    not backup_protected_ids[vm_id]
    msg := {
        "rule_id": metadata.id,
        "resource_id": vm_id,
        "resource_type": "Microsoft.Compute/virtualMachines",
        "resource_name": object.get(vm, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("VM '%s' has no Azure Backup vault protection configured.", [object.get(vm, "name", "")]),
        "evidence": {
            "backupConfigured": false
        },
        "chain_role": metadata.chain_role
    }
}

# SQL servers without backup
violation contains msg if {
    srv := input.sql_servers[_]
    srv_id := object.get(srv, "id", "")
    not backup_protected_ids[srv_id]
    msg := {
        "rule_id": metadata.id,
        "resource_id": srv_id,
        "resource_type": "Microsoft.Sql/servers",
        "resource_name": object.get(srv, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("SQL Server '%s' has no Azure Backup vault protection configured.", [object.get(srv, "name", "")]),
        "evidence": {
            "backupConfigured": false
        },
        "chain_role": metadata.chain_role
    }
}
