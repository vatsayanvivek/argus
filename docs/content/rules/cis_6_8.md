# cis_6_8 — NSG flow logs not enabled for all NSGs

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

NSG flow logs record all network traffic passing through a Network Security Group. Without flow logs, network-based lateral movement and data exfiltration cannot be detected.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-12 |
| NIST 800-207 | — |
| CIS Azure | 6.8 |
| MITRE ATT&CK Technique | T1562.008 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/networking/cis_6_8.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/networking/cis_6_8.rego){ .md-button }
