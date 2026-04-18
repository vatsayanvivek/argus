# zt_int_002 — API Management lacks a system-assigned managed identity

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** ENABLER

## Description

API Management instances without a managed identity must store backend credentials (Key Vault secrets, storage keys, service principal secrets) inline in named-value stores. System-assigned identity lets APIM fetch secrets from Key Vault at runtime with no static credentials anywhere in the APIM config, collapsing the shared-secret attack surface.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1) |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/integration/zt_int_002.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_002.rego){ .md-button }
