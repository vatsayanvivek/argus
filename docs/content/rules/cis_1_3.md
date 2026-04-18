# cis_1_3 — Ensure guest users are reviewed on a regular basis

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Checks that there is at least one access review covering guest users in the tenant. Stale guest accounts accumulate risk.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-2(3) |
| NIST 800-207 | Tenet 6 - Continuous authentication and authorization |
| CIS Azure | 1.3 |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_3.rego){ .md-button }
