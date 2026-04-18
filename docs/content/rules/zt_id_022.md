# zt_id_022 — User risk policy not enabled in Identity Protection

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

User risk policies detect compromised accounts by analyzing signals such as leaked credentials and impossible travel. Without a Conditional Access policy evaluating user risk levels, compromised identities remain active indefinitely.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 2 - All communication secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1110 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_022.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_022.rego){ .md-button }
