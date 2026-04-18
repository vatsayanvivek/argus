# cis_8_3 — Ensure Key Vault has diagnostic settings enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Key Vault should have diagnostic settings configured to stream audit events to a Log Analytics workspace or storage account.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-2 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 8.3 |
| MITRE ATT&CK Technique | T1555 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/keyvault/cis_8_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/keyvault/cis_8_3.rego){ .md-button }
