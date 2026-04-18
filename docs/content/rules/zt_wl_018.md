# zt_wl_018 — App Service has remote debugging enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

App Services with remote debugging enabled open additional ports and debugging endpoints accessible over the network. This provides an attacker with a direct command-and-control channel into the application runtime.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CM-7 |
| NIST 800-207 | Tenet 5 - Monitor and measure integrity and security posture of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1219 |
| MITRE ATT&CK Tactic | Command and Control |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_018.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_018.rego){ .md-button }
