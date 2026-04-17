package argus.azure.zt.identity.zt_id_024

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_024",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "Service principal credentials not rotated within 90 days",
    "description": "Service principal password credentials older than 90 days increase the risk of credential compromise through exposure in logs, configuration files, or developer workstations. Regular rotation limits the window of exploitation.",
    "zt_tenet": "Tenet 3",
    "nist_800_207": "Tenet 3 - Access granted on a per-session basis",
    "nist_800_53": "IA-5(1)",
    "cis_rule": "",
    "mitre_technique": "T1552",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

ninety_days_ago := time.add_date(time.now_ns(), 0, 0, -90)

has_stale_credential(sp) if {
    creds := object.get(sp, "password_credentials", [])
    cred := creds[_]
    start := object.get(cred, "startDateTime", "")
    is_string(start)
    start != ""
    time.parse_rfc3339_ns(start) < ninety_days_ago
}

violation contains msg if {
    sp := input.service_principals[_]
    has_stale_credential(sp)
    display_name := object.get(sp, "displayName", object.get(sp, "appId", "unknown"))
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sp, "id", ""),
        "resource_type": "Microsoft.Graph/servicePrincipals",
        "resource_name": display_name,
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Service principal '%s' has password credentials older than 90 days. Credentials should be rotated regularly to limit exposure.", [display_name]),
        "evidence": {
            "displayName": display_name,
            "appId": object.get(sp, "appId", "")
        },
        "chain_role": metadata.chain_role
    }
}
