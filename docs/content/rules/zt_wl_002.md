# zt_wl_002 — Container image pulled from public registry

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

Images not pulled from a private Azure Container Registry bypass supply chain controls, image scanning, and content trust.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SA-12 |
| NIST 800-207 | Tenet 3 - Access granted per-session |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1195 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_002.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_002.rego){ .md-button }
