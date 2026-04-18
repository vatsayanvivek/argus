# cis_6_9 — Public IP addresses not associated with DDoS protection

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Public IP addresses without DDoS protection are vulnerable to volumetric and protocol-level denial-of-service attacks that can render services unavailable.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-5 |
| NIST 800-207 | — |
| CIS Azure | 6.9 |
| MITRE ATT&CK Technique | T1498 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/networking/cis_6_9.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/networking/cis_6_9.rego){ .md-button }
