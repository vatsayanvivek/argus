# cis_8_4 — Ensure Key Vault uses private endpoints

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Key Vaults should be accessible only via private endpoints so that secret retrieval traffic never crosses the public internet.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 2 - Secure communication regardless of network |
| CIS Azure | 8.4 |
| MITRE ATT&CK Technique | T1555 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/keyvault/cis_8_4.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/keyvault/cis_8_4.rego){ .md-button }
