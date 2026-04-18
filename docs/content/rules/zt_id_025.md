# zt_id_025 — Managed identity not used where available

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

App Services and Function Apps that do not use managed identities rely on stored credentials (connection strings, secrets) for Azure resource access. Managed identities eliminate credential management and reduce the attack surface for credential theft.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2 |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_025.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_025.rego){ .md-button }
