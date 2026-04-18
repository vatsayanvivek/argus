# zt_net_015 — VPN Gateway not using IKEv2 or OpenVPN protocol

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

VPN gateways using only SSTP or IKEv1 are limited to older, less secure protocols. IKEv2 and OpenVPN provide stronger encryption, faster reconnection, and broader platform support. Missing IKEv2 may indicate use of deprecated protocols vulnerable to downgrade attacks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8(1) |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_015.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_015.rego){ .md-button }
