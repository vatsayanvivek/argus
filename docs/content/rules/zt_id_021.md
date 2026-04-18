# zt_id_021 — PIM role activation lacks approval workflow

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Privileged Identity Management role assignments for highly privileged roles should require an approval workflow. Without approval, a compromised account can self-activate Global Administrator or equivalent roles instantly.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6(1) |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_021.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_021.rego){ .md-button }
