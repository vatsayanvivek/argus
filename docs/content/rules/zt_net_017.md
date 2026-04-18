# zt_net_017 — Front Door does not have WAF policy attached

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ENABLER

## Description

Azure Front Door without a Web Application Firewall policy exposes backend services to OWASP Top 10 attacks, bot traffic, and volumetric DDoS at the application layer. WAF policies on Front Door are a critical edge defense.

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

Rule defined at `policies/azure/zt/network/zt_net_017.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_017.rego){ .md-button }
