# cis_3_4 — Ensure default network access rule is Deny on storage accounts

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Storage accounts should use default-deny network ACLs and explicitly allow trusted subnets or service endpoints. Default-allow exposes data to the entire internet.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-4 |
| NIST 800-207 | Tenet 2 - Secure communication |
| CIS Azure | 3.4 |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/storage/cis_3_4.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/storage/cis_3_4.rego){ .md-button }
