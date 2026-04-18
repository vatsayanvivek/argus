# zt_net_009 — Storage account network default action is Allow

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Storage accounts with defaultAction=Allow are reachable from any source on the Internet; network ACLs must deny by default.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_009.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_009.rego){ .md-button }
