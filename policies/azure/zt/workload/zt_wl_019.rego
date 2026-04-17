package argus.azure.zt.workload.zt_wl_019

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_019",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "App Service does not require client certificates",
    "description": "App Services that do not require client certificates rely solely on server-side authentication, missing mutual TLS verification. Requiring client certificates provides device-level attestation and reduces the risk of man-in-the-middle attacks.",
    "zt_tenet": "Tenet 3",
    "nist_800_207": "Tenet 3 - Access to individual enterprise resources granted on a per-session basis",
    "nist_800_53": "IA-3",
    "cis_rule": "",
    "mitre_technique": "T1557",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    app := input.app_services[_]
    props := object.get(app, "properties", {})
    object.get(props, "clientCertEnabled", false) != true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(app, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": object.get(app, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("App Service '%s' does not require client certificates (mutual TLS).", [object.get(app, "name", "")]),
        "evidence": {
            "clientCertEnabled": object.get(props, "clientCertEnabled", false)
        },
        "chain_role": metadata.chain_role
    }
}
