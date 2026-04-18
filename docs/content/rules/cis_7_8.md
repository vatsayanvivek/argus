# cis_7_8 — Virtual Machine managed disks use customer-managed keys

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

VM managed disks encrypted with platform-managed keys do not provide key rotation control. Customer-managed keys in Key Vault enable centralized key lifecycle management and revocation.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28 |
| NIST 800-207 | — |
| CIS Azure | 7.8 |
| MITRE ATT&CK Technique | T1005 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/vms/cis_7_8.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/vms/cis_7_8.rego){ .md-button }
