# cis_9_5 — Ensure App Service uses managed identity

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** ENABLER

## Description

App Services should authenticate to Azure resources using managed identity instead of connection strings or secrets embedded in configuration.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5 |
| NIST 800-207 | Tenet 6 - Dynamic authentication |
| CIS Azure | 9.5 |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/appservice/cis_9_5.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/appservice/cis_9_5.rego){ .md-button }
