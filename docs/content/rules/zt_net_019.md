# zt_net_019 — Subnet has no Network Security Group associated

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ENABLER

## Description

Subnets without an associated Network Security Group have no network-level access control, allowing unrestricted traffic flow. Every subnet except dedicated service subnets (GatewaySubnet, AzureFirewallSubnet, AzureBastionSubnet) must have an NSG.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_019.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_019.rego){ .md-button }
