# zt_wl_012 — Container Registry has admin account enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Container Registries with the admin account enabled expose a shared credential pair that cannot be scoped or audited per-principal. Disabling the admin account and using Azure AD tokens or managed identities enforces least-privilege and individual accountability.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6 |
| NIST 800-207 | Tenet 6 - Authentication and authorization are dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_012.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_012.rego){ .md-button }
