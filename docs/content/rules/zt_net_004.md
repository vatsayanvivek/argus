# zt_net_004 — VNet peering without central firewall inspection

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Peered VNets that transit without a central firewall (hub-and-spoke with inspection) allow lateral movement between blast radii.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7(8) |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1021 |
| MITRE ATT&CK Tactic | Lateral Movement |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_004.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_004.rego){ .md-button }
