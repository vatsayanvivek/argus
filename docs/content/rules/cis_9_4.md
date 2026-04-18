# cis_9_4 — Ensure App Service has HTTP/2 enabled

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Pillar:** Workload · **Chain role:** ENABLER

## Description

HTTP/2 provides improved performance and more robust transport security features over HTTP/1.1.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8 |
| NIST 800-207 | Tenet 2 - Secure communication |
| CIS Azure | 9.4 |
| MITRE ATT&CK Technique | T1499 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/appservice/cis_9_4.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/appservice/cis_9_4.rego){ .md-button }
