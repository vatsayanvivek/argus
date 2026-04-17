package argus.azure.zt.workload.zt_wl_005

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_005",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "App Service allows HTTP (not HTTPS only)",
    "description": "App Services serving plaintext HTTP expose session cookies and auth tokens to network-positioned attackers.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured",
    "nist_800_53": "SC-8",
    "cis_rule": "",
    "mitre_technique": "T1557",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    app := input.app_services[_]
    props := object.get(app, "properties", {})
    object.get(props, "httpsOnly", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(app, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": object.get(app, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("App Service '%s' has httpsOnly=false.", [object.get(app, "name", "")]),
        "evidence": {
            "httpsOnly": object.get(props, "httpsOnly", false)
        },
        "chain_role": metadata.chain_role
    }
}
