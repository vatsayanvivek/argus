package argus.azure.zt.network.zt_net_014

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_014",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Application Gateway does not have WAF enabled",
    "description": "Application Gateway without Web Application Firewall (WAF) leaves web applications exposed to OWASP Top 10 attacks including SQL injection and cross-site scripting. WAF is a critical layer-7 defense in the Zero Trust network model.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    gw := input.app_gateways[_]
    props := object.get(gw, "properties", {})
    waf := object.get(props, "webApplicationFirewallConfiguration", null)
    not is_waf_enabled(waf)
    name := object.get(gw, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(gw, "id", ""),
        "resource_type": "Microsoft.Network/applicationGateways",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Application Gateway '%s' does not have WAF enabled. Web applications are exposed to layer-7 attacks.", [name]),
        "evidence": {
            "gateway_name": name,
            "waf_configuration": waf
        },
        "chain_role": metadata.chain_role
    }
}

is_waf_enabled(waf) if {
    waf != null
    object.get(waf, "enabled", false) == true
}
