package argus.azure.zt.identity.zt_id_011

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_011",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Identity",
    "title": "App Registration holds high-privilege Microsoft Graph permissions",
    "description": "Application-level Microsoft Graph permissions such as RoleManagement.ReadWrite.Directory or Application.ReadWrite.All grant tenant-wide access without a user context, so a single compromised App Registration becomes a path to Global Administrator. The participating chain is CHAIN-002.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "AC-6(1)",
    "cis_rule": "",
    "mitre_technique": "T1550",
    "mitre_tactic": "Privilege Escalation",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

graph_resource_id := "00000003-0000-0000-c000-000000000000"

dangerous_permissions := {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All"
}

violation contains msg if {
    app := input.app_registrations[_]
    rras := object.get(app, "required_resource_access", [])
    rra := rras[_]
    object.get(rra, "resource_app_id", "") == graph_resource_id
    perms := object.get(rra, "permissions", [])
    perm := perms[_]
    object.get(perm, "type", "") == "Role"
    perm_id := object.get(perm, "id", "")
    perm_name := dangerous_permissions[perm_id]
    display_name := object.get(app, "display_name", object.get(app, "app_id", ""))
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(app, "id", ""),
        "resource_type": "Microsoft.Graph/applications",
        "resource_name": display_name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("App Registration '%s' holds dangerous Graph permission '%s' (%s) — path to Global Administrator escalation.", [display_name, perm_name, perm_id]),
        "evidence": {
            "appId": object.get(app, "app_id", ""),
            "permission_id": perm_id,
            "permission_name": perm_name,
            "resource": "Microsoft Graph"
        },
        "chain_role": metadata.chain_role
    }
}
