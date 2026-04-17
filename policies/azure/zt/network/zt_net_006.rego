package argus.azure.zt.network.zt_net_006

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_net_006",
    "source": "argus-zt",
    "severity": "HIGH",
    "pillar": "Network",
    "title": "Virtual Machine has a direct public IP",
    "description": "VMs with direct public IPs bypass central ingress controls and dramatically increase attack surface; traffic should instead traverse Azure Firewall, App Gateway, or Load Balancer with WAF.",
    "zt_tenet": "Tenet 5",
    "nist_800_207": "Tenet 5 - Integrity monitored",
    "nist_800_53": "SC-7",
    "cis_rule": "",
    "mitre_technique": "T1190",
    "mitre_tactic": "Initial Access",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    pip := input.public_ips[_]
    assoc := object.get(pip, "associated_to", "")
    contains(assoc, "/virtualMachines/")
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(pip, "id", ""),
        "resource_type": "Microsoft.Network/publicIPAddresses",
        "resource_name": object.get(pip, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Public IP '%s' is attached directly to VM '%s'.", [object.get(pip, "name", ""), assoc]),
        "evidence": {
            "public_ip": object.get(pip, "ipAddress", ""),
            "associated_to": assoc
        },
        "chain_role": metadata.chain_role
    }
}
