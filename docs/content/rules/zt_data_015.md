# zt_data_015 — SQL Database TDE uses service-managed key instead of customer-managed

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

SQL Servers using service-managed keys for Transparent Data Encryption delegate key lifecycle control to Microsoft. Customer-managed keys in Azure Key Vault provide full control over key rotation, revocation, and destruction, meeting regulatory requirements for data sovereignty.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28(1) |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1486 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_015.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_015.rego){ .md-button }
