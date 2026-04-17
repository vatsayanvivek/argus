package argus.azure.zt.workload.zt_wl_018

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_018",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "App Service has remote debugging enabled",
    "description": "App Services with remote debugging enabled open additional ports and debugging endpoints accessible over the network. This provides an attacker with a direct command-and-control channel into the application runtime.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Monitor and measure integrity and security posture of assets",
    "nist_800_53": "CM-7",
    "cis_rule": "",
    "mitre_technique": "T1219",
    "mitre_tactic": "Command and Control",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    app := input.app_services[_]
    props := object.get(app, "properties", {})
    sc := object.get(props, "siteConfig", {})
    object.get(sc, "remoteDebuggingEnabled", false) == true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(app, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": object.get(app, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("App Service '%s' has remote debugging enabled, exposing a debug endpoint.", [object.get(app, "name", "")]),
        "evidence": {
            "remoteDebuggingEnabled": true
        },
        "chain_role": metadata.chain_role
    }
}
