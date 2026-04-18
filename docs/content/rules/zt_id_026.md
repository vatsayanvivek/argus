# zt_id_026 — No access reviews configured for privileged roles

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Without periodic access reviews on privileged directory roles, stale or unnecessary role assignments accumulate over time, expanding the blast radius of credential compromise and violating least-privilege principles.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-2 |
| NIST 800-207 | Tenet 4 - Access to resources is determined by dynamic policy |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_026.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_026.rego){ .md-button }
