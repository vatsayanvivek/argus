package argus.azure.zt.identity.zt_id_002

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_002",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "Service not using managed identity",
    "description": "Workloads without managed identity are forced to store credentials in config or code, dramatically increasing the risk of credential theft and lateral movement.",
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
    msg := build_msg(vm, "Microsoft.Compute/virtualMachines")
}

violation contains msg if {
    app := input.app_services[_]
    not has_identity(app)
    msg := build_msg(app, "Microsoft.Web/sites")
}

violation contains msg if {
    fn := input.function_apps[_]
    not has_identity(fn)
    msg := build_msg(fn, "Microsoft.Web/sites/functions")
}

has_identity(resource) if {
    ident := object.get(resource, "identity", null)
    ident != null
    ident_type := object.get(ident, "type", "None")
    ident_type != "None"
}

build_msg(resource, rtype) := msg if {
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(resource, "id", ""),
        "resource_type": rtype,
        "resource_name": object.get(resource, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Resource '%s' (%s) is not using a managed identity; credentials must be stored elsewhere.", [object.get(resource, "name", ""), rtype]),
        "evidence": {
            "identity": object.get(resource, "identity", null)
        },
        "chain_role": metadata.chain_role
    }
}
