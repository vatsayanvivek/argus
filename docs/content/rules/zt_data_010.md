# zt_data_010 — Storage account not using customer-managed keys (BYOK)

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Using Microsoft-managed keys is insufficient for regulated data; customer-managed keys in Key Vault give the tenant control over key rotation and destruction.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-12 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1486 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_010.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_010.rego){ .md-button }
