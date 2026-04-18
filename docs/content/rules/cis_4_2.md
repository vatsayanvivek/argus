# cis_4_2 — Ensure Transparent Data Encryption is enabled on SQL databases

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

TDE encrypts SQL databases at rest. Without TDE, stolen backups or database files can be read directly.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28(1) |
| NIST 800-207 | Tenet 3 - Per-session authenticated access |
| CIS Azure | 4.2 |
| MITRE ATT&CK Technique | T1486 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/database/cis_4_2.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/database/cis_4_2.rego){ .md-button }
