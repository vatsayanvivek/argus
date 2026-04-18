# cis_8_6 — Key Vault keys have rotation policy configured

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Keys without a rotation policy may remain static for extended periods. Automatic key rotation reduces the risk of key compromise and ensures cryptographic hygiene.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-12 |
| NIST 800-207 | — |
| CIS Azure | 8.6 |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/keyvault/cis_8_6.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/keyvault/cis_8_6.rego){ .md-button }
