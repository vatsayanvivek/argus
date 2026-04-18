# cis_5_8 — Activity Log retention set to 365 days or more

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

Activity Log retention below 365 days limits the ability to investigate historical control-plane operations during long-dwell-time breaches.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-11 |
| NIST 800-207 | — |
| CIS Azure | 5.8 |
| MITRE ATT&CK Technique | T1070 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/logging/cis_5_8.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/logging/cis_5_8.rego){ .md-button }
