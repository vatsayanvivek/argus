# zt_wl_015 — AKS cluster does not use Azure RBAC for Kubernetes authorization

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

AKS clusters without Azure RBAC for Kubernetes authorization rely on local Kubernetes RBAC alone, bypassing Azure AD conditional access and unified audit. Enabling Azure RBAC ties Kubernetes API access to Azure AD identities and policies.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 6 - Authentication and authorization are dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_015.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_015.rego){ .md-button }
