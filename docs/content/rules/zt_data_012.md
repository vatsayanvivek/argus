# zt_data_012 — SQL Server auditing not enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

SQL Servers without auditing enabled lack visibility into database operations, making it impossible to detect unauthorized access, data exfiltration, or tampering. Enabling auditing ensures all queries and administrative actions are logged for forensic analysis.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-12 |
| NIST 800-207 | Tenet 5 - Monitor and measure integrity and security posture of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1565 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_012.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_012.rego){ .md-button }
