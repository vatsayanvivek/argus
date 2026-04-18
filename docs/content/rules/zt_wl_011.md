# zt_wl_011 — App Service uses legacy Easy Auth v1 without client auth enforcement

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

App Services using authsettings (v1) with clientAuthEnabled=false skip client certificate validation. When combined with App Registration high-privilege Graph permissions and storage with default-allow network rules, they form a multi-step path to tenant data (CHAIN-002).

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_011.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_011.rego){ .md-button }
