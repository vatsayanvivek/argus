# zt_net_022 — Private DNS Zone has no virtual-network link — private endpoints unreachable

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** ENABLER

## Description

Private endpoints rely on Private DNS Zone VNet links to resolve <resource>.privatelink.<region>.<service> to the private endpoint IP. Without a VNet link, clients inside the VNet fall back to the public IP — defeating the private endpoint's entire purpose. Every Private DNS zone used for privatelink must be linked to the consuming VNets.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 3 - All communication is secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557.002 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_022.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_022.rego){ .md-button }
