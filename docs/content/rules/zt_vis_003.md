# zt_vis_003 — Microsoft Defender for Cloud plans on Free tier

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Defender Free tier provides only basic recommendations; Standard tier is required for threat detection, workload protection, and regulatory coverage.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562.001 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_003.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_003.rego){ .md-button }
