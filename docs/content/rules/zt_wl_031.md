# zt_wl_031 — Batch account accepts public-endpoint pool access (no private endpoint)

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

Azure Batch accounts with publicNetworkAccess='Enabled' expose the pool-management and task-submission endpoints to the internet. Any user with a valid Batch account key or Entra token can queue compute work — including from compromised laptops. Put Batch accounts on private endpoints; the performance cost is zero and the attack surface drops to zero.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-4, SC-7 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_031.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_031.rego){ .md-button }
