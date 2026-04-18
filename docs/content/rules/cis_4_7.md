# cis_4_7 — SQL Database has long-term backup retention configured

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

SQL Databases without long-term backup retention are vulnerable to data loss from ransomware or destructive attacks. Long-term retention ensures recovery beyond the default short-term window.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9 |
| NIST 800-207 | — |
| CIS Azure | 4.7 |
| MITRE ATT&CK Technique | T1486 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/database/cis_4_7.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/database/cis_4_7.rego){ .md-button }
