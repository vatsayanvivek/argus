# cis_8_7 — Key Vault uses private endpoint

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Key Vaults accessible over the public internet expose secrets, keys, and certificates to network-based attacks. Private endpoints restrict access to the virtual network.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | — |
| CIS Azure | 8.7 |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/keyvault/cis_8_7.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/keyvault/cis_8_7.rego){ .md-button }
