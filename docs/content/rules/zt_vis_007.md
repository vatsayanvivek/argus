# zt_vis_007 — No Microsoft Sentinel deployment found

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Sentinel provides SIEM and SOAR capabilities that correlate signals across identity, workload, and network; its absence means there is no unified detection fabric.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IR-4 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_007.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_007.rego){ .md-button }
