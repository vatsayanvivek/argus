# zt_vis_010 — Just-in-Time VM access not configured

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

JIT VM access enforces time-bound, source-restricted NSG rules for management ports; without it, administrative access paths are always open.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6 |
| NIST 800-207 | Tenet 6 - Dynamic access policy |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_010.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_010.rego){ .md-button }
