# cis_2_3 — Ensure Microsoft Defender for SQL Servers is set to Standard

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Defender for SQL detects anomalous queries, SQL injection, and brute force against Azure SQL.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 7 - Asset posture collection |
| CIS Azure | 2.3 |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/defender/cis_2_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/defender/cis_2_3.rego){ .md-button }
