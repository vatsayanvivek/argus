package argus.azure.zt.identity.zt_id_025

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_025",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "Managed identity not used where available",
    "description": "App Services and Function Apps that do not use managed identities rely on stored credentials (connection strings, secrets) for Azure resource access. Managed identities eliminate credential management and reduce the attack surface for credential theft.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "IA-2",
    "cis_rule": "",
    "mitre_technique": "T1078.004",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

has_managed_identity(res) if {
    identity := object.get(res, "identity", {})
    id_type := object.get(identity, "type", "None")
    id_type != "None"
    id_type != ""
}

has_managed_identity(res) if {
    props := object.get(res, "properties", {})
    identity := object.get(props, "identity", {})
    id_type := object.get(identity, "type", "None")
    id_type != "None"
    id_type != ""
}

violation contains msg if {
    app := input.app_services[_]
    not has_managed_identity(app)
    name := object.get(app, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(app, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("App Service '%s' does not use a managed identity. Stored credentials increase the risk of credential theft.", [name]),
        "evidence": {
            "resource_name": name,
            "identity": object.get(app, "identity", null)
        },
        "chain_role": metadata.chain_role
    }
}

violation contains msg if {
    func := input.function_apps[_]
    not has_managed_identity(func)
    name := object.get(func, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(func, "id", ""),
        "resource_type": "Microsoft.Web/sites/functions",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Function App '%s' does not use a managed identity. Stored credentials increase the risk of credential theft.", [name]),
        "evidence": {
            "resource_name": name,
            "identity": object.get(func, "identity", null)
        },
        "chain_role": metadata.chain_role
    }
}
