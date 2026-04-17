package argus.azure.zt.network.zt_net_008

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_008",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Application Gateway without WAF",
    "description": "Application Gateways without the Web Application Firewall tier / policy do not protect backends from OWASP Top 10 exploits.",
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
    agw := input.app_gateways[_]
    props := object.get(agw, "properties", {})
    not has_waf(props)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(agw, "id", ""),
        "resource_type": "Microsoft.Network/applicationGateways",
        "resource_name": object.get(agw, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Application Gateway '%s' does not have WAF configured.", [object.get(agw, "name", "")]),
        "evidence": {
            "firewallPolicy": object.get(props, "firewallPolicy", null),
            "wafConfig": object.get(props, "webApplicationFirewallConfiguration", null)
        },
        "chain_role": metadata.chain_role
    }
}

has_waf(props) if {
    fp := object.get(props, "firewallPolicy", null)
    fp != null
}

has_waf(props) if {
    waf := object.get(props, "webApplicationFirewallConfiguration", {})
    object.get(waf, "enabled", false) == true
}
