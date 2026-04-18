# cis_2_8 — Ensure Microsoft Defender for Resource Manager is set to Standard

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Defender for Resource Manager detects suspicious ARM operations such as credential dumping, resource creation in unusual regions, and anomalous role assignments.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 7 - Asset posture collection |
| CIS Azure | 2.8 |
| MITRE ATT&CK Technique | T1098 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/defender/cis_2_8.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/defender/cis_2_8.rego){ .md-button }
