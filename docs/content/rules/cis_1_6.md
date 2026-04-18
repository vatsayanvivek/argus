# cis_1_6 — Ensure that 'Guest invite restrictions' is set to admins only

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** ENABLER

## Description

External invitations should be restricted so that not every member user can invite guests. Unrestricted invites enable easy persistence and unwanted data sharing.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 2 - All communication secured regardless of network |
| CIS Azure | 1.6 |
| MITRE ATT&CK Technique | T1136.003 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_6.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_6.rego){ .md-button }
