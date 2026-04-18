# zt_id_017 — Cross-tenant access settings allow inbound trust by default

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Default cross-tenant access settings that permit inbound trust allow external tenants to satisfy MFA and device compliance claims, enabling attackers from compromised partner tenants to bypass local Conditional Access controls.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-17 |
| NIST 800-207 | Tenet 1 - All data sources and computing services are resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1199 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_017.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_017.rego){ .md-button }
