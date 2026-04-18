# zt_id_020 — Administrative units not used for role scoping

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

Administrative units allow scoping directory role assignments to specific subsets of users, groups, or devices. Without administrative units, all role assignments are tenant-wide, violating least-privilege principles.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6(2) |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_020.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_020.rego){ .md-button }
