package argus.azure.zt.identity.zt_id_013

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_id_013",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Identity",
    "title": "Conditional Access policies do not define named locations",
    "description": "Named locations allow Conditional Access policies to differentiate requests by geography or IP range. Without named locations, policies cannot enforce location-based restrictions, weakening the Zero Trust verification posture.",
    "zt_tenet": "Tenet 3",
    "nist_800_207": "Tenet 3 - Access granted on a per-session basis",
    "nist_800_53": "AC-2(12)",
    "cis_rule": "",
    "mitre_technique": "T1078",
    "mitre_tactic": "Initial Access",
    "chain_role": "ENABLER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

has_locations(policy) if {
    conditions := object.get(policy, "conditions", {})
    locations := object.get(conditions, "locations", {})
    include := object.get(locations, "includeLocations", [])
    count(include) > 0
}

violation contains msg if {
    policies := object.get(input, "conditional_access_policies", [])
    count(policies) > 0
    policies_with_locations := [p | p := policies[_]; has_locations(p)]
    count(policies_with_locations) == 0
    sub := object.get(input, "subscription", {})
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sub, "id", ""),
        "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccessPolicies",
        "resource_name": "tenant",
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("None of the %d Conditional Access policies define named locations; location-based controls cannot be enforced.", [count(policies)]),
        "evidence": {
            "total_policies": count(policies),
            "policies_with_locations": 0
        },
        "chain_role": metadata.chain_role
    }
}
