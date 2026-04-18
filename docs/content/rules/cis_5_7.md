# cis_5_7 — Azure Monitor Diagnostic Settings captures all categories

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

Diagnostic settings must capture all log categories to ensure complete visibility. Missing categories create blind spots that attackers can exploit to evade detection.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-12 |
| NIST 800-207 | — |
| CIS Azure | 5.7 |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/logging/cis_5_7.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/logging/cis_5_7.rego){ .md-button }
