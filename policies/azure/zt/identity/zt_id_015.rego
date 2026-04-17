package argus.azure.zt.identity.zt_id_015

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_015",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Identity",
    "title": "Self-service password reset allows weak authentication methods",
    "description": "When SSPR permits email or security questions as verification methods, attackers who compromise a mailbox or social-engineer answers can reset passwords without MFA. Only strong methods such as authenticator app or phone should be allowed.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "IA-5(1)",
    "cis_rule": "",
    "mitre_technique": "T1110",
    "mitre_tactic": "Credential Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

weak_methods := {"email", "securityQuestion"}

violation contains msg if {
    settings := object.get(input, "tenant_settings", {})
    object.get(settings, "sspr_enabled", false) == true
    methods := object.get(settings, "sspr_methods", [])
    weak := [m | m := methods[_]; weak_methods[m]]
    count(weak) > 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Self-service password reset allows weak method(s): %s. These can be exploited to bypass MFA.", [concat(", ", {m | m := weak[_]})]),
        "evidence": {
            "sspr_enabled": true,
            "sspr_methods": methods,
            "weak_methods_found": weak
        },
        "chain_role": metadata.chain_role
    }
}
