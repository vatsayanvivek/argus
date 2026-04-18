# cis_5_6 — Ensure activity log alert exists for Security Solution changes

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

An alert should fire when Microsoft.Security/securitySolutions resources are created or deleted so that tampering with security posture is detected.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-6 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 5.6 |
| MITRE ATT&CK Technique | T1562.001 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/logging/cis_5_6.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/logging/cis_5_6.rego){ .md-button }
