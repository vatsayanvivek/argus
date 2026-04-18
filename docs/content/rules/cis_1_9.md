# cis_1_9 — Ensure admins are notified on password resets

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Admins should be notified whenever self-service password resets occur on privileged accounts to detect unauthorized resets quickly.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-2 |
| NIST 800-207 | Tenet 7 - Collect information about asset security posture |
| CIS Azure | 1.9 |
| MITRE ATT&CK Technique | T1098 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_9.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_9.rego){ .md-button }
