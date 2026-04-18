# cis_4_5 — Ensure 'Enforce SSL connection' is enabled for PostgreSQL

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

PostgreSQL flexible/single servers must enforce SSL so credentials and query data are encrypted in transit.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8(1) |
| NIST 800-207 | Tenet 2 - Secure communication |
| CIS Azure | 4.5 |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/database/cis_4_5.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/database/cis_4_5.rego){ .md-button }
