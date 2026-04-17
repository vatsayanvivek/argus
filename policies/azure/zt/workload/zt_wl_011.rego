package argus.azure.zt.workload.zt_wl_011

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_011",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Workload",
    "title": "App Service uses legacy Easy Auth v1 without client auth enforcement",
    "description": "App Services using authsettings (v1) with clientAuthEnabled=false skip client certificate validation. When combined with App Registration high-privilege Graph permissions and storage with default-allow network rules, they form a multi-step path to tenant data (CHAIN-002).",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured",
    "nist_800_53": "IA-2",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Persistence",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    app := input.app_services[_]
    auth := object.get(app, "authsettings", {})
    object.get(auth, "enabled", false) == true
    object.get(auth, "clientAuthEnabled", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(app, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": object.get(app, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("App Service '%s' uses legacy authsettings v1 without clientAuthEnabled; participates in CHAIN-002 (App Registration takeover).", [object.get(app, "name", "")]),
        "evidence": {
            "authsettings_enabled": true,
            "clientAuthEnabled": object.get(auth, "clientAuthEnabled", false),
            "defaultProvider": object.get(auth, "defaultProvider", "")
        },
        "chain_role": metadata.chain_role
    }
}
