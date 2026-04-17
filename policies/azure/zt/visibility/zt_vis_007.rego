package argus.azure.zt.visibility.zt_vis_007

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_vis_007",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Visibility",
    "title": "No Microsoft Sentinel deployment found",
    "description": "Sentinel provides SIEM and SOAR capabilities that correlate signals across identity, workload, and network; its absence means there is no unified detection fabric.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "IR-4",
    "cis_rule": "",
    "mitre_technique": "T1562",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    not has_sentinel
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.SecurityInsights/onboardingStates",
        "resource_name": object.get(sub, "display_name", "subscription"),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": "No Microsoft Sentinel deployment found in this subscription.",
        "evidence": {
            "sentinel_found": false
        },
        "chain_role": metadata.chain_role
    }
}

has_sentinel if {
    r := input.resources[_]
    t := lower(object.get(r, "type", ""))
    contains(t, "securityinsights")
}

has_sentinel if {
    r := input.resources[_]
    t := lower(object.get(r, "type", ""))
    contains(t, "sentinel")
}
