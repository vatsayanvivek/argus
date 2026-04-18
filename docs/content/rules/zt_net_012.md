# zt_net_012 — Azure Firewall threat intelligence mode not set to Alert and Deny

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Azure Firewall threat intelligence can operate in Off, Alert, or Alert and Deny mode. Only Alert and Deny (Deny) actively blocks connections to known malicious IPs and domains. Alert-only mode logs but does not prevent command-and-control traffic.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7(8) |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1071 |
| MITRE ATT&CK Tactic | Command and Control |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_012.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_012.rego){ .md-button }
