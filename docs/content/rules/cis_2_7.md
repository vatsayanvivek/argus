# cis_2_7 — Ensure Microsoft Defender for DNS is set to Standard

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Defender for DNS detects DNS-based data exfiltration, beaconing to known C2 infrastructure, and name resolution to malicious domains.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 7 - Asset posture collection |
| CIS Azure | 2.7 |
| MITRE ATT&CK Technique | T1071.004 |
| MITRE ATT&CK Tactic | Command and Control |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/defender/cis_2_7.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/defender/cis_2_7.rego){ .md-button }
