# cis_5_9 — Network Security Group flow log retention set to >= 90 days

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

NSG flow log retention below 90 days limits forensic investigation of network-based attacks including lateral movement and data exfiltration.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-11 |
| NIST 800-207 | — |
| CIS Azure | 5.9 |
| MITRE ATT&CK Technique | T1070 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/logging/cis_5_9.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/logging/cis_5_9.rego){ .md-button }
