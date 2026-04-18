# zt_net_003 — Subnet has no associated Network Security Group

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ENABLER

## Description

Subnets without an NSG rely entirely on adjacent resource controls; defense-in-depth requires at least one NSG layer on every subnet.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1021 |
| MITRE ATT&CK Tactic | Lateral Movement |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_003.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_003.rego){ .md-button }
