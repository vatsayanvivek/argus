package argus.azure.zt.network.zt_net_017

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_017",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Front Door does not have WAF policy attached",
    "description": "Azure Front Door without a Web Application Firewall policy exposes backend services to OWASP Top 10 attacks, bot traffic, and volumetric DDoS at the application layer. WAF policies on Front Door are a critical edge defense.",
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
    res := input.resources[_]
    object.get(res, "type", "") == "Microsoft.Network/frontDoors"
    props := object.get(res, "properties", {})
    endpoints := object.get(props, "frontendEndpoints", [])
    endpoint := endpoints[_]
    waf_link := object.get(endpoint, "webApplicationFirewallPolicyLink", null)
    waf_link == null
    name := object.get(res, "name", "unknown")
    ep_name := object.get(endpoint, "name", "unknown")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(res, "id", ""),
        "resource_type": "Microsoft.Network/frontDoors",
        "resource_name": name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Front Door '%s' frontend endpoint '%s' has no WAF policy attached. Backend services are exposed to application-layer attacks.", [name, ep_name]),
        "evidence": {
            "front_door_name": name,
            "endpoint_name": ep_name,
            "webApplicationFirewallPolicyLink": null
        },
        "chain_role": metadata.chain_role
    }
}
