# zt_id_016 — Guest users have excessive directory permissions

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Guest users with assigned directory roles violate least-privilege principles. External identities should access resources through scoped entitlements, not broad directory roles that enable lateral movement and privilege escalation.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6 |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_016.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_016.rego){ .md-button }
