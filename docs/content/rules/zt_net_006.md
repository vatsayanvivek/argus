# zt_net_006 — Virtual Machine has a direct public IP

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ANCHOR

## Description

VMs with direct public IPs bypass central ingress controls and dramatically increase attack surface; traffic should instead traverse Azure Firewall, App Gateway, or Load Balancer with WAF.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_006.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_006.rego){ .md-button }
