# zt_data_031 — Storage Data Lake Gen2 container has no ACL-based access control

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Data Lake Gen2 containers use either RBAC (coarse, at container scope) or POSIX ACLs (fine, per-path). Containers with no ACLs configured fall back to blanket RBAC — any user with Storage Blob Data Reader sees every path, even folders meant for specific teams. For lake zones containing cross-team or regulated data, ACLs at the path level are expected. Note: requires Hierarchical Namespace enabled on the account.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3(7), AC-6 |
| NIST 800-207 | Tenet 4 - Access to individual enterprise resources is granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1005 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_031.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_031.rego){ .md-button }
