# cis_1_7 — Ensure no service principal credentials are expired

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Service principal passwordCredentials with endDateTime in the past indicate stale credentials that may still exist in configuration files, CI systems, or secret stores.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1) |
| NIST 800-207 | Tenet 6 - Dynamic authentication |
| CIS Azure | 1.7 |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_7.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_7.rego){ .md-button }
