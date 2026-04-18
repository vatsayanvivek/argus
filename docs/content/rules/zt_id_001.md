# zt_id_001 — Service Principal credential never expires

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Service principal password credentials without expiration create persistent backdoors that attackers can leverage indefinitely once stolen.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5 |
| NIST 800-207 | Tenet 2 - All communication secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1098 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_001.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_001.rego){ .md-button }
