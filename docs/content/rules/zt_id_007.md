# zt_id_007 — No PIM assignments configured

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Absence of Privileged Identity Management (PIM) indicates that privileged roles are standing rather than just-in-time; this violates least-privilege principles.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6 |
| NIST 800-207 | Tenet 6 - Dynamic access policy |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_007.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_007.rego){ .md-button }
