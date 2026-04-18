# cis_2_6 — Ensure Microsoft Defender for Key Vault is set to Standard

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Defender for Key Vault detects anomalous secret and key access patterns that may indicate credential theft.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 7 - Asset posture collection |
| CIS Azure | 2.6 |
| MITRE ATT&CK Technique | T1555 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/defender/cis_2_6.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/defender/cis_2_6.rego){ .md-button }
