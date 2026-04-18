# zt_vis_013 — NSG flow log retention period is less than 90 days

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

NSG flow logs record network traffic metadata. Retention below 90 days limits the ability to investigate lateral movement and data exfiltration after a breach.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-11 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1070 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_013.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_013.rego){ .md-button }
