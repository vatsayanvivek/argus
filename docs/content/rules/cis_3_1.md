# cis_3_1 — Ensure 'Secure transfer required' is enabled on storage accounts

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Storage accounts should only accept connections over HTTPS. HTTP traffic to blob/table/queue endpoints is trivially interceptable.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8 |
| NIST 800-207 | Tenet 2 - All communication secured regardless of network |
| CIS Azure | 3.1 |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/storage/cis_3_1.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/storage/cis_3_1.rego){ .md-button }
