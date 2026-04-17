package argus.azure.zt.workload.zt_wl_004

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_004",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Workload",
    "title": "Function App has no authentication enabled",
    "description": "Function Apps without App Service Authentication (Easy Auth) enabled expose triggers to the public Internet without any identity gate.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured",
    "nist_800_53": "IA-2",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    fn := input.function_apps[_]
    not has_auth(fn)
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(fn, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": object.get(fn, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Function App '%s' has no authentication configured.", [object.get(fn, "name", "")]),
        "evidence": {
            "authsettings": object.get(fn, "authsettings", null),
            "authsettingsV2": object.get(fn, "authsettingsV2", null)
        },
        "chain_role": metadata.chain_role
    }
}

has_auth(fn) if {
    auth := object.get(fn, "authsettings", {})
    object.get(auth, "enabled", false) == true
}

has_auth(fn) if {
    auth := object.get(fn, "authsettingsV2", {})
    gp := object.get(auth, "globalValidation", {})
    object.get(gp, "requireAuthentication", false) == true
}
