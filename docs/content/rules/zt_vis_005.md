# zt_vis_005 — Activity log retention appears insufficient

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

A very small activity log sample (<100 events) suggests short retention or limited ingestion; compliance frameworks require 90+ days of activity history.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-11 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_005.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_005.rego){ .md-button }
