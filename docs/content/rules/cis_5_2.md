# cis_5_2 — Ensure Activity Log retention is 365 days or more

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

The Activity Log should be retained for at least 365 days to support investigation of incidents that are discovered months after the fact.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-11 |
| NIST 800-207 | Tenet 7 - Continuous monitoring |
| CIS Azure | 5.2 |
| MITRE ATT&CK Technique | T1070 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/logging/cis_5_2.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/logging/cis_5_2.rego){ .md-button }
