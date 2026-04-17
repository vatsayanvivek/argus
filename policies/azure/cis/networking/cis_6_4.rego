package argus.azure.cis.cis_6_4

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_4",
	"source": "argus-cis",
	"severity": "MEDIUM",
	"pillar": "Visibility",
	"title": "Ensure Network Watcher is enabled",
	"description": "Azure Network Watcher provides diagnostic and visualization tools for network traffic. Without it, packet captures and flow analytics are unavailable.",
	"zt_tenet": "Tenet 7",
	"nist_800_207": "Tenet 7 - Collect posture information",
	"nist_800_53": "AU-12",
	"cis_rule": "6.4",
	"mitre_technique": "T1046",
	"mitre_tactic": "Discovery",
	"chain_role": "ENABLER",
	"frameworks": ["nist-800-207", "cis-azure-2.0", "nist-800-53"],
}

has_network_watcher if {
	nw := input.network_watchers[_]
	nw.id != ""
}

violation contains msg if {
	not has_network_watcher
	msg := {
		"rule_id": metadata.id,
		"resource_id": input.subscription.id,
		"resource_type": "Microsoft.Network/networkWatchers",
		"resource_name": "network_watcher",
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Subscription '%v' has no Network Watcher resources. Packet capture and flow log capabilities are unavailable.", [input.subscription.name]),
		"evidence": {
			"subscription_id": input.subscription.id,
			"network_watchers_count": count(object.get(input, "network_watchers", [])),
		},
		"chain_role": metadata.chain_role,
	}
}
