# zt_wl_019 — App Service does not require client certificates

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

App Services that do not require client certificates rely solely on server-side authentication, missing mutual TLS verification. Requiring client certificates provides device-level attestation and reduces the risk of man-in-the-middle attacks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-3 |
| NIST 800-207 | Tenet 3 - Access to individual enterprise resources granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_019.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_019.rego){ .md-button }
