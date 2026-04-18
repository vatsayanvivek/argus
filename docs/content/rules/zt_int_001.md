# zt_int_001 — API Management instance accepts weak TLS on the gateway

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

API Management's gateway terminates client TLS and proxies to backend services. A TLS policy that permits 1.0/1.1 or weak ciphers exposes every API behind the gateway to downgrade attacks. Modern clients support TLS 1.2+; there is no legitimate reason to leave weaker protocols enabled on a publicly reachable gateway.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8, SC-13 |
| NIST 800-207 | Tenet 3 - All communication is secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/integration/zt_int_001.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_001.rego){ .md-button }
