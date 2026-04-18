# zt_wl_003 — AKS API server is publicly reachable without IP allowlist

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

AKS clusters with a public API endpoint and no authorized IP ranges (or wildcard ranges) expose the Kubernetes control plane to the Internet.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_003.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_003.rego){ .md-button }
