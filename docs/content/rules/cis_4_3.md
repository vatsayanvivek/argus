# cis_4_3 — Ensure SQL server Advanced Data Security is enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

SQL security alert policies detect anomalous activities such as SQL injection and unusual access patterns.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 4.3 |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/database/cis_4_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/database/cis_4_3.rego){ .md-button }
