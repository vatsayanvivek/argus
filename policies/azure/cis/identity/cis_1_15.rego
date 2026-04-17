package argus.azure.cis.cis_1_15

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_15",
	"source": "argus-cis",
	"severity": "CRITICAL",
	"pillar": "Identity",
	"title": "Ensure app registrations do not have high-privilege Graph permissions",
	"description": "Application registrations with high-privilege Microsoft Graph application (Role) permissions can read or write tenant-wide data. These are prime persistence targets.",
	"zt_tenet": "Tenet 6",
	"nist_800_207": "Tenet 6 - Least privilege for non-human identities",
	"nist_800_53": "AC-6(1)",
	"cis_rule": "1.15",
	"mitre_technique": "T1098.001",
	"mitre_tactic": "Persistence",
	"chain_role": "ANCHOR",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

graph_resource_id := "00000003-0000-0000-c000-000000000000"

dangerous_graph_roles := {
	"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
	"06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
	"1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
	"62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
	"741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
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
	role_name := dangerous_graph_roles[perm_id]
	display_name := object.get(app, "display_name", object.get(app, "app_id", ""))
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(app, "id", ""),
		"resource_type": "Microsoft.AAD/applications",
		"resource_name": display_name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("App registration '%v' holds dangerous Graph application permission '%v' (id=%v). This grants tenant-wide non-interactive access.", [display_name, role_name, perm_id]),
		"evidence": {
			"app_id": object.get(app, "app_id", ""),
			"display_name": display_name,
			"graph_permission_id": perm_id,
			"graph_permission_name": role_name,
			"permission_type": object.get(perm, "type", ""),
		},
		"chain_role": metadata.chain_role,
	}
}
