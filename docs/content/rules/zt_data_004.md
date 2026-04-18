# zt_data_004 — Key Vault soft delete disabled

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Data · **Chain role:** ENABLER

## Description

Key Vaults without soft delete are vulnerable to accidental or malicious permanent deletion, destroying keys and secrets that protect downstream resources.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1485 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_004.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_004.rego){ .md-button }
