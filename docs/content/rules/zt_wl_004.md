# zt_wl_004 — Function App has no authentication enabled

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

Function Apps without App Service Authentication (Easy Auth) enabled expose triggers to the public Internet without any identity gate.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_004.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_004.rego){ .md-button }
