# zt_vis_018 — No Azure Monitor action groups configured

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

Action groups define notification recipients and automation targets for alert rules. Without at least one action group, alerts cannot reach operators or trigger automated response.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IR-6 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_018.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_018.rego){ .md-button }
