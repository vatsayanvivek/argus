# cis_3_5 — Ensure storage accounts use private endpoints

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Storage accounts should be reachable only via private endpoints so data plane traffic never traverses the public internet.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 2 - Secure communication |
| CIS Azure | 3.5 |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/storage/cis_3_5.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/storage/cis_3_5.rego){ .md-button }
