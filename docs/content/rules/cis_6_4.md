# cis_6_4 — Ensure Network Watcher is enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Azure Network Watcher provides diagnostic and visualization tools for network traffic. Without it, packet captures and flow analytics are unavailable.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-12 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 6.4 |
| MITRE ATT&CK Technique | T1046 |
| MITRE ATT&CK Tactic | Discovery |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/networking/cis_6_4.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/networking/cis_6_4.rego){ .md-button }
