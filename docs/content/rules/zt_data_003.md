# zt_data_003 — SQL Server auditing not enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Without SQL auditing, data access patterns are invisible; exfiltration and unauthorized reads cannot be detected or reconstructed.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-2 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_003.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_003.rego){ .md-button }
