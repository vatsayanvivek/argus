# cis_9_2 — Ensure App Service minimum TLS version is 1.2

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

App Services should require a minimum TLS version of 1.2. Older versions contain known cryptographic weaknesses.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8(1) |
| NIST 800-207 | Tenet 2 - Secure communication |
| CIS Azure | 9.2 |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/appservice/cis_9_2.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/appservice/cis_9_2.rego){ .md-button }
