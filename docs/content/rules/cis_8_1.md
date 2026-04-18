# cis_8_1 — Ensure Key Vault has soft delete and purge protection enabled

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Without soft delete or purge protection, an attacker with Contributor access to a Key Vault can irrecoverably destroy keys and secrets, breaking every service that depends on them.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9 |
| NIST 800-207 | Tenet 3 - Per-session authenticated access |
| CIS Azure | 8.1 |
| MITRE ATT&CK Technique | T1485 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/keyvault/cis_8_1.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/keyvault/cis_8_1.rego){ .md-button }
