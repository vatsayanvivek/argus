package argus.azure.zt.workload.zt_wl_008

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_008",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "App Service has remote debugging enabled",
    "description": "Remote debugging exposes interactive debugging endpoints to attackers and should never be left on in production.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "CM-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    app := input.app_services[_]
    props := object.get(app, "properties", {})
    cfg := object.get(props, "siteConfig", {})
    object.get(cfg, "remoteDebuggingEnabled", false) == true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(app, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": object.get(app, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("App Service '%s' has remote debugging enabled.", [object.get(app, "name", "")]),
        "evidence": {
            "remoteDebuggingEnabled": true,
            "remoteDebuggingVersion": object.get(cfg, "remoteDebuggingVersion", "")
        },
        "chain_role": metadata.chain_role
    }
}
