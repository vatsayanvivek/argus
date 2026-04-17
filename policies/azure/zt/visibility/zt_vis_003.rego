package argus.azure.zt.visibility.zt_vis_003

import future.keywords.if
import future.keywords.contains
import future.keywords.in

metadata := {
    "id": "zt_vis_003",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Visibility",
    "title": "Microsoft Defender for Cloud plans on Free tier",
    "description": "Defender Free tier provides only basic recommendations; Standard tier is required for threat detection, workload protection, and regulatory coverage.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SI-4",
    "cis_rule": "",
    "mitre_technique": "T1562.001",
    "mitre_tactic": "Defense Evasion",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

# Aggregating rule: emit ONE finding listing every Defender plan
# that is currently on Free tier. The full list lives in evidence.
violation contains msg if {
    plans := object.get(input, "defender_plans", {})
    free_services := [service |
        some service
        plan_info := plans[service]
        plan_of(plan_info) == "Free"
    ]
    count(free_services) > 0

    sub := object.get(input, "subscription", {})
    sub_id := object.get(sub, "id", "unknown")

    msg := {
        "rule_id": metadata.id,
        "resource_id": sprintf("%s/providers/Microsoft.Security/pricings", [sub_id]),
        "resource_type": "Microsoft.Security/pricings",
        "resource_name": "defender-plans",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("%d Microsoft Defender plan(s) on Free tier: %v. Threat detection and workload protection are degraded.", [count(free_services), free_services]),
        "evidence": {
            "affected_count": count(free_services),
            "free_services": free_services
        },
        "chain_role": metadata.chain_role
    }
}

plan_of(info) := p if {
    is_string(info)
    p := info
}

plan_of(info) := p if {
    is_object(info)
    p := object.get(info, "plan", object.get(info, "pricingTier", ""))
}
