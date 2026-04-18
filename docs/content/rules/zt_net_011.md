# zt_net_011 — Azure Firewall not deployed in hub virtual network

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ENABLER

## Description

Azure Firewall provides centralized network traffic filtering and threat intelligence. Without a firewall in the hub network, east-west and north-south traffic flows unfiltered, enabling lateral movement and command-and-control channels.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7(5) |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1090 |
| MITRE ATT&CK Tactic | Command and Control |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_011.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_011.rego){ .md-button }
