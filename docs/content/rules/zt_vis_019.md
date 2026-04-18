# zt_vis_019 — Application Insights not configured for web applications

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

Application Insights provides request tracing, dependency tracking, and exception logging for web apps. Without it, application-layer attacks such as injection and exploitation go undetected.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-12 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_019.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_019.rego){ .md-button }
