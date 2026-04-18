# cis_3_6 — Ensure soft delete is enabled for blob service

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Blob soft delete protects against accidental or malicious deletion by retaining deleted blobs for a configurable period.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9 |
| NIST 800-207 | Tenet 7 - Continuous monitoring and recovery |
| CIS Azure | 3.6 |
| MITRE ATT&CK Technique | T1485 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/storage/cis_3_6.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/storage/cis_3_6.rego){ .md-button }
