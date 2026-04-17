package argus.azure.cis.cis_1_25

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_1_25",
	"source": "argus-cis",
	"severity": "LOW",
	"pillar": "Identity",
	"title": "Role assignments use groups instead of individual users",
	"description": "Direct user role assignments create management overhead and increase the risk of orphaned permissions. Group-based assignments enable centralized access governance and simplify auditing.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "AC-2",
	"cis_rule": "1.25",
	"mitre_technique": "T1078",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "AMPLIFIER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

violation contains msg if {
	ra := input.role_assignments[_]
	pt := object.get(ra, "principalType", "")
	pt == "User"
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(ra, "id", ""),
		"resource_type": "Microsoft.Authorization/roleAssignments",
		"resource_name": object.get(ra, "principalId", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Role assignment '%v' is assigned directly to a user instead of a group. Group-based assignment enables centralized access governance.", [object.get(ra, "id", "")]),
		"evidence": {
			"assignment_id": object.get(ra, "id", ""),
			"principal_type": pt,
			"principal_id": object.get(ra, "principalId", ""),
			"role_definition_id": object.get(ra, "roleDefinitionId", ""),
		},
		"chain_role": metadata.chain_role,
	}
}
