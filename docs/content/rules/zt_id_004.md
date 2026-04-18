# zt_id_004 — Cross-tenant access unrestricted

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Unrestricted cross-tenant access settings allow external tenants to consume resources without scoped B2B policy, enabling supply chain compromise.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 4 - Access determined by dynamic policy |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1199 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_004.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_004.rego){ .md-button }
