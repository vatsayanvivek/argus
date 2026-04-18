# zt_vis_008 — No alert on Owner role assignment

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Owner role grants are the highest-privilege change an attacker makes during escalation; activity log shows no owner-role events, indicating no alerting on this operation.

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

Rule defined at `policies/azure/zt/visibility/zt_vis_008.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_008.rego){ .md-button }
