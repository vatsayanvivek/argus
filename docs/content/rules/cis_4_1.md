# cis_4_1 — Ensure 'Auditing' is set to On for SQL servers

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

SQL auditing tracks database events and writes them to an audit log for compliance and threat detection.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-2 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 4.1 |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/database/cis_4_1.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/database/cis_4_1.rego){ .md-button }
