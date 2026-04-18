# zt_id_018 — Identity Protection sign-in risk policy not enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Sign-in risk policies in Identity Protection evaluate real-time signals such as atypical travel, anonymous IP, and password spray patterns. Without a Conditional Access policy referencing sign-in risk levels, compromised sessions go undetected.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 2 - All communication secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_018.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_018.rego){ .md-button }
