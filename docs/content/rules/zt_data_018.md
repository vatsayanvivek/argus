# zt_data_018 — Event Hub namespace does not use customer-managed key encryption

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Event Hub namespaces without customer-managed key encryption rely on Microsoft-managed keys, limiting tenant control over the encryption lifecycle. Using Key Vault-backed keys ensures the organization can rotate, revoke, and audit access to the encryption material.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28(1) |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_018.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_018.rego){ .md-button }
