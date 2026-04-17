package argus.azure.zt.zt_net_024

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "zt_net_024",
	"source": "argus-zt",
	"severity": "LOW",
	"pillar": "Network",
	"title": "NAT Gateway has no idle timeout configured for long-lived connections",
	"description": "NAT Gateway with the default idle timeout (4 minutes) cuts long-running backend connections — common for database replication, message-bus consumers, and gRPC streams — triggering reconnect storms that can mask attack traffic inside normal reconnect noise. Explicit idle-timeout configuration (30-120 minutes for stable workloads) both stabilises connections and makes anomalous connection churn easier to spot.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - The enterprise collects as much information as possible about the current state of assets",
	"nist_800_53": "AU-2",
	"cis_rule": "",
	"mitre_technique": "T1562",
	"mitre_tactic": "Defense Evasion",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "argus-zt"],
}

violation contains msg if {
	resource := input.resources[_]
	lower(resource.type) == "microsoft.network/natgateways"
	props := object.get(resource, "properties", {})
	idle := object.get(props, "idleTimeoutInMinutes", 4)
	idle < 30

	msg := {
		"rule_id": metadata.id,
		"resource_id": resource.id,
		"resource_type": resource.type,
		"resource_name": resource.name,
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("NAT Gateway '%s' has idleTimeoutInMinutes=%d. Increase to 30+ for backend workloads.", [resource.name, idle]),
		"evidence": {"idleTimeoutInMinutes": idle},
		"chain_role": metadata.chain_role,
	}
}
