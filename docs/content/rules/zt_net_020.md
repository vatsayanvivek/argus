# zt_net_020 — Virtual network peering allows forwarded traffic from remote

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

VNet peering with allowForwardedTraffic enabled lets the remote network forward traffic from third-party networks into the local VNet, bypassing local egress controls. This can be abused for lateral movement or to route command-and-control traffic through a trusted peering.

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

Rule defined at `policies/azure/zt/network/zt_net_020.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_020.rego){ .md-button }
