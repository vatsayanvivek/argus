# zt_vis_012 — No Azure Monitor alert rules configured for critical operations

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

Alert rules trigger notifications when critical operations occur. Without metric or activity log alerts, anomalous behaviour will not be detected in real time.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-6 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_012.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_012.rego){ .md-button }
