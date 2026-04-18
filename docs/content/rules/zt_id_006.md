# zt_id_006 — No enabled conditional access policies

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Without enabled conditional access, authentication decisions rely solely on credentials. Dynamic policy is foundational to Zero Trust.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 4 - Access determined by dynamic policy |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_006.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_006.rego){ .md-button }
