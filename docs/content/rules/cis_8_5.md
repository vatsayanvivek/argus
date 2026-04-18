# cis_8_5 — Key Vault secrets have expiration date set

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Secrets without expiration dates can remain valid indefinitely. Setting expiration enforces credential rotation and limits the window of compromise for leaked secrets.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5 |
| NIST 800-207 | — |
| CIS Azure | 8.5 |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/keyvault/cis_8_5.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/keyvault/cis_8_5.rego){ .md-button }
