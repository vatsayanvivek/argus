# zt_data_007 — SQL Server firewall allows all Azure services

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

The 0.0.0.0-0.0.0.0 firewall rule opens the SQL server to every subscription on Azure, vastly expanding the blast radius beyond the intended tenant.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_007.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_007.rego){ .md-button }
