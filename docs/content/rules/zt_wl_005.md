# zt_wl_005 — App Service allows HTTP (not HTTPS only)

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

App Services serving plaintext HTTP expose session cookies and auth tokens to network-positioned attackers.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_005.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_005.rego){ .md-button }
