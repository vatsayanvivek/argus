# zt_vis_015 — SQL Server audit log retention less than 90 days

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

SQL Server auditing captures database-level events. Retention below 90 days limits the ability to investigate data tampering and unauthorized access after a breach.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-11 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1565 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_015.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_015.rego){ .md-button }
