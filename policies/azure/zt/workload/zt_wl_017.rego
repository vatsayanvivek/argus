package argus.azure.zt.workload.zt_wl_017

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_wl_017",
    "source": "argus-zt",
    "severity": "MEDIUM",
    "pillar": "Workload",
    "title": "Function App uses outdated runtime version",
    "description": "Function Apps running outdated language runtime versions miss critical security patches and may contain known vulnerabilities exploitable for initial access. Keeping runtimes up to date reduces the attack surface.",
    "zt_tenet": "Tenet 7",
    "nist_800_207": "Tenet 7 - Collect information about the current state of assets",
    "nist_800_53": "SI-2",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "AMPLIFIER",
    "frameworks": ["nist-800-207", "argus-zt"]
}

# Minimum acceptable versions
min_dotnet := "v6.0"
min_node := "~18"
min_python := "3.10"

violation contains msg if {
    fa := input.function_apps[_]
    props := object.get(fa, "properties", {})
    sc := object.get(props, "siteConfig", {})
    version_info := outdated_runtime(sc)
    version_info.outdated == true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(fa, "id", ""),
        "resource_type": "Microsoft.Web/sites",
        "resource_name": object.get(fa, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Function App '%s' uses outdated %s runtime version '%s'.", [object.get(fa, "name", ""), version_info.runtime, version_info.version]),
        "evidence": {
            "runtime": version_info.runtime,
            "version": version_info.version,
            "netFrameworkVersion": object.get(sc, "netFrameworkVersion", ""),
            "nodeVersion": object.get(sc, "nodeVersion", ""),
            "pythonVersion": object.get(sc, "pythonVersion", "")
        },
        "chain_role": metadata.chain_role
    }
}

outdated_runtime(sc) := {"outdated": true, "runtime": ".NET", "version": v} if {
    v := object.get(sc, "netFrameworkVersion", "")
    v != ""
    v < min_dotnet
}

outdated_runtime(sc) := {"outdated": true, "runtime": "Node.js", "version": v} if {
    v := object.get(sc, "nodeVersion", "")
    v != ""
    v < min_node
}

outdated_runtime(sc) := {"outdated": true, "runtime": "Python", "version": v} if {
    v := object.get(sc, "pythonVersion", "")
    v != ""
    v < min_python
}
