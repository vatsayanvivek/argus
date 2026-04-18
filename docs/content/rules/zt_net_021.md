# zt_net_021 — VPN Gateway uses a deprecated Basic SKU

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

VPN Gateway Basic SKU is end-of-life for commercial use as of Q3 2025. Basic gateways lack BGP support, active-active failover, and the modern IKEv2 cipher suite. Workloads still on Basic should migrate to VpnGw1/2/3 (or ErGw1AZ for ExpressRoute). Basic will stop receiving security patches.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_021.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_021.rego){ .md-button }
