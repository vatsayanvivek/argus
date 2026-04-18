# cis_5_3 — Ensure activity log alert exists for Create Policy Assignment

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

An alert should fire when Microsoft.Authorization/policyAssignments/write events occur so that changes to policy posture are detected.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-6 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 5.3 |
| MITRE ATT&CK Technique | T1562.001 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/logging/cis_5_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/logging/cis_5_3.rego){ .md-button }
