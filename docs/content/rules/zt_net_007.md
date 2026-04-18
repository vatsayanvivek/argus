# zt_net_007 — VNet missing DDoS protection

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** ENABLER

## Description

Without DDoS Protection Standard, public-facing workloads in a VNet only receive best-effort platform DDoS mitigation, which is insufficient for critical apps.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-5 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1499 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_007.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_007.rego){ .md-button }
