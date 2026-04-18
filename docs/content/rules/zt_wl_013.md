# zt_wl_013 — Container Registry allows public network access

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

Container Registries that do not disable public network access are reachable from the internet, expanding the attack surface for image pull/push operations. Restricting access to private endpoints limits exposure to trusted networks only.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Monitor and measure integrity and security posture of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_013.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_013.rego){ .md-button }
