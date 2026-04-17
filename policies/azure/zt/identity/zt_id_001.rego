package argus.azure.zt.identity.zt_id_001

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
    "id": "zt_id_001",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Service Principal credential never expires",
    "description": "Service principal password credentials without expiration create persistent backdoors that attackers can leverage indefinitely once stolen.",
    "zt_tenet": "Tenet 2",
    "nist_800_207": "Tenet 2 - All communication secured regardless of network location",
    "nist_800_53": "IA-5",
    "cis_rule": "",
    "mitre_technique": "T1098",
    "mitre_tactic": "Persistence",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

is_never_expiring(end_date) if {
    end_date == null
}

is_never_expiring(end_date) if {
    is_string(end_date)
    end_date >= "2099"
}

has_never_expiring_credential(sp) if {
    creds := object.get(sp, "passwordCredentials", [])
    cred := creds[_]
    end_date := object.get(cred, "endDateTime", null)
    is_never_expiring(end_date)
}

violation contains msg if {
    affected := [s | s := input.service_principals[_]; has_never_expiring_credential(s)]
    count(affected) > 0
    sub := object.get(input, "subscription", {})
    tenant_id := object.get(sub, "tenant_id", "unknown")
    sample := [name |
        some i
        i < 25
        sp := affected[i]
        name := object.get(sp, "displayName", object.get(sp, "appId", ""))
    ]
    msg := {
        "rule_id": metadata.id,
        "resource_id": sprintf("tenant:%s/never-expiring-sp-creds", [tenant_id]),
        "resource_type": "Microsoft.Graph/servicePrincipals",
        "resource_name": "tenant",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("%d service principal(s) have at least one credential that never expires. These act as persistent backdoors if compromised.", [count(affected)]),
        "evidence": {
            "affected_count": count(affected),
            "tenant_id": tenant_id,
            "sample_service_principals": sample
        },
        "chain_role": metadata.chain_role
    }
}
