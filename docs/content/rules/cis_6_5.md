# cis_6_5 — Ensure NSG flow logs are enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

NSG flow logs record IP traffic flowing through network security groups, essential for forensic analysis and detection.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-12 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 6.5 |
| MITRE ATT&CK Technique | T1046 |
| MITRE ATT&CK Tactic | Discovery |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/networking/cis_6_5.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/networking/cis_6_5.rego){ .md-button }
