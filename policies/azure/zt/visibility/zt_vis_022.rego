package argus.azure.zt.zt_vis_022

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
	"id": "zt_vis_022",
	"source": "argus-zt",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "No Activity Log alert for Key Vault 'listKeys' or 'listSecrets' operations",
	"description": "An attacker with secrets-access permission on any Key Vault in the subscription can quietly enumerate and exfiltrate every secret via listKeys/listSecrets. Without an alert, these bulk-enumeration calls are indistinguishable from legitimate provisioning traffic. Alert on them targeting subscription scope + a pager action group.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - The enterprise collects as much information as possible about the current state of assets",
	"nist_800_53": "AU-6, SI-4",
	"cis_rule": "",
	"mitre_technique": "T1552.007",
	"mitre_tactic": "Credential Access",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

watched_ops := [
	"microsoft.keyvault/vaults/secrets/listsecrets/action",
	"microsoft.keyvault/vaults/keys/listkeys/action",
]

violation contains msg if {
	watched := watched_ops[_]
	not listing_alert_exists(watched)

	sub := object.get(input, "subscription", {})
	sub_id := object.get(sub, "id", "unknown")

	msg := {
		"rule_id": metadata.id,
		"resource_id": sprintf("subscription:%s", [sub_id]),
		"resource_type": "Microsoft.Insights/activityLogAlerts",
		"resource_name": sprintf("missing alert for %s", [watched]),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("No Activity Log alert matches operationName %q. Wire an alert + action group.", [watched]),
		"evidence": {"missing_operation": watched, "subscription_id": sub_id},
		"chain_role": metadata.chain_role,
	}
}

listing_alert_exists(op) if {
	alert := input.resources[_]
	lower(alert.type) == "microsoft.insights/activitylogalerts"
	props := object.get(alert, "properties", {})
	object.get(props, "enabled", false) == true
	conditions := object.get(object.get(props, "condition", {}), "allOf", [])
	some c in conditions
	lower(object.get(c, "field", "")) == "operationname"
	lower(object.get(c, "equals", "")) == op
}
