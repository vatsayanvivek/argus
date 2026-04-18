# zt_id_023 — MFA registration policy not enforced for all users

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Without a Conditional Access policy requiring MFA registration for all users, new or existing accounts may operate without multi-factor authentication, creating an entry point for password-based attacks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2(1) |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_023.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_023.rego){ .md-button }
