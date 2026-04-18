# cis_6_3 — Ensure UDP services are not exposed to the internet

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Inbound UDP from the internet should be restricted. UDP services are common DDoS amplification vectors and often unauthenticated.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 2 - Secure communication |
| CIS Azure | 6.3 |
| MITRE ATT&CK Technique | T1498 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/networking/cis_6_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/networking/cis_6_3.rego){ .md-button }
