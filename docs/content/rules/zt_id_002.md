# zt_id_002 — Service not using managed identity

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

Workloads without managed identity are forced to store credentials in config or code, dramatically increasing the risk of credential theft and lateral movement.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_002.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_002.rego){ .md-button }
