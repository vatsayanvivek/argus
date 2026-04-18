# zt_net_005 — No Azure Firewall or NVA deployed

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** ENABLER

## Description

Without a central firewall, outbound traffic cannot be inspected and egress filtering cannot be enforced against command-and-control channels.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7(8) |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_005.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_005.rego){ .md-button }
