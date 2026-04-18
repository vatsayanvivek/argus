# zt_data_017 — Critical resources have no Azure Backup configured

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Virtual machines and SQL servers without associated Azure Backup vault protection are vulnerable to permanent data loss from ransomware, accidental deletion, or destructive attacks. Configuring backup ensures recoverability within defined RPO/RTO targets.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9 |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1486 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_017.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_017.rego){ .md-button }
