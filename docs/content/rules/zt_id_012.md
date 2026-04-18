# zt_id_012 — No emergency access (break-glass) accounts configured

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Identity · **Chain role:** ANCHOR

## Description

Emergency access accounts (break-glass) ensure administrative access when normal authentication is unavailable. Microsoft recommends at least two cloud-only emergency accounts excluded from conditional access. Without them, a tenant lockout becomes unrecoverable.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6(1) |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_012.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_012.rego){ .md-button }
