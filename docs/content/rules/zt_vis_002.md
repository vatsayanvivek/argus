# zt_vis_002 — No Log Analytics workspace in subscription

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Without a Log Analytics workspace, diagnostic logs have nowhere to be stored or queried; SIEM and detection pipelines cannot function.

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

Rule defined at `policies/azure/zt/visibility/zt_vis_002.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_002.rego){ .md-button }
