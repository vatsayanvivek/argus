package argus.azure.zt.identity.zt_id_012

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_012",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Identity",
    "title": "No emergency access (break-glass) accounts configured",
    "description": "Emergency access accounts (break-glass) ensure administrative access when normal authentication is unavailable. Microsoft recommends at least two cloud-only emergency accounts excluded from conditional access. Without them, a tenant lockout becomes unrecoverable.",
    "zt_tenet": "Tenet 6",
    "nist_800_207": "Tenet 6 - Dynamic access policy and least privilege",
    "nist_800_53": "AC-6(1)",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

is_break_glass(user) if {
    dn := lower(object.get(user, "display_name", ""))
    contains(dn, "break glass")
}

is_break_glass(user) if {
    dn := lower(object.get(user, "display_name", ""))
    contains(dn, "emergency")
}

violation contains msg if {
    users := object.get(input, "users", [])
    bg_accounts := [u |
        u := users[_]
        is_break_glass(u)
        object.get(u, "account_enabled", false) == true
    ]
    count(bg_accounts) < 2
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/tenant",
        "resource_name": object.get(sub, "display_name", "tenant"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Only %d active break-glass account(s) found; at least 2 are required for emergency access resilience.", [count(bg_accounts)]),
        "evidence": {
            "break_glass_count": count(bg_accounts)
        },
        "chain_role": metadata.chain_role
    }
}
