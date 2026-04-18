# cis_3_8 — Ensure storage account diagnostic logs are enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Storage accounts should have diagnostic settings configured to capture read/write/delete operations for audit and detection.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-2 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 3.8 |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/storage/cis_3_8.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/storage/cis_3_8.rego){ .md-button }
