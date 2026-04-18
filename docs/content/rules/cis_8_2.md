# cis_8_2 — Ensure Key Vault keys have rotation policies

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Keys stored in Key Vault should have an automatic rotation policy configured so that cryptographic material does not stagnate.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-12 |
| NIST 800-207 | Tenet 6 - Dynamic authentication |
| CIS Azure | 8.2 |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/keyvault/cis_8_2.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/keyvault/cis_8_2.rego){ .md-button }
