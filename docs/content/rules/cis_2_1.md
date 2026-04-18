# cis_2_1 — Ensure Microsoft Defender for Servers is set to Standard

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Defender for Servers provides threat detection, vulnerability assessment, and JIT VM access. Without it VMs lack runtime protection.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 2.1 |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/defender/cis_2_1.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/defender/cis_2_1.rego){ .md-button }
