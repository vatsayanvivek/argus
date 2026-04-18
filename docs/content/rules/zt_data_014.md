# zt_data_014 — Key Vault does not have purge protection enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Key Vaults without purge protection allow permanently deleted keys, secrets, and certificates to be irrecoverably lost immediately. Enabling purge protection enforces a mandatory retention period, preventing malicious or accidental permanent deletion of cryptographic material.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-12 |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1485 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_014.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_014.rego){ .md-button }
