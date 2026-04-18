# cis_7_9 — Unattached disks are encrypted with customer-managed key

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Unattached managed disks may still contain sensitive data. Encrypting them with customer-managed keys ensures data remains protected even when disks are detached from VMs.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28 |
| NIST 800-207 | — |
| CIS Azure | 7.9 |
| MITRE ATT&CK Technique | T1005 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/vms/cis_7_9.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/vms/cis_7_9.rego){ .md-button }
