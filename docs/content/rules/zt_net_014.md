# zt_net_014 — Application Gateway does not have WAF enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ENABLER

## Description

Application Gateway without Web Application Firewall (WAF) leaves web applications exposed to OWASP Top 10 attacks including SQL injection and cross-site scripting. WAF is a critical layer-7 defense in the Zero Trust network model.

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

Rule defined at `policies/azure/zt/network/zt_net_014.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_014.rego){ .md-button }
