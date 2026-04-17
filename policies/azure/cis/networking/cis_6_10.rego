package argus.azure.cis.cis_6_10

import future.keywords.if
import future.keywords.contains

metadata := {
	"id": "cis_6_10",
	"source": "argus-cis",
	"severity": "HIGH",
	"pillar": "Network",
	"title": "Web Application Firewall (WAF) is enabled for Application Gateway",
	"description": "Application Gateway without WAF enabled allows OWASP Top 10 attacks such as SQL injection and cross-site scripting to reach backend web applications.",
	"zt_tenet": "",
	"nist_800_207": "",
	"nist_800_53": "SC-7",
	"cis_rule": "6.10",
	"mitre_technique": "T1190",
	"mitre_tactic": "Initial Access",
	"chain_role": "ENABLER",
	"frameworks": ["cis-azure-2.0", "nist-800-53"],
}

has_waf(gw) if {
	waf := object.get(object.get(gw, "properties", {}), "webApplicationFirewallConfiguration", {})
	object.get(waf, "enabled", false) == true
}

has_waf(gw) if {
	fp := object.get(object.get(gw, "properties", {}), "firewallPolicy", {})
	object.get(fp, "id", "") != ""
}

violation contains msg if {
	gw := input.app_gateways[_]
	not has_waf(gw)
	msg := {
		"rule_id": metadata.id,
		"resource_id": object.get(gw, "id", ""),
		"resource_type": "Microsoft.Network/applicationGateways",
		"resource_name": object.get(gw, "name", ""),
		"severity": metadata.severity,
		"title": metadata.title,
		"detail": sprintf("Application Gateway '%v' does not have WAF enabled. Backend web applications are exposed to OWASP Top 10 attacks.", [object.get(gw, "name", "")]),
		"evidence": {
			"app_gateway_id": object.get(gw, "id", ""),
			"waf_enabled": false,
		},
		"chain_role": metadata.chain_role,
	}
}
