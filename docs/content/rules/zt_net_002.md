# zt_net_002 — NSG allows RDP (3389) from the Internet

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Network · **Chain role:** ANCHOR

## Description

Exposing RDP to the Internet is a top initial access vector; BlueKeep and brute force against exposed RDP remain widely exploited.

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

Rule defined at `policies/azure/zt/network/zt_net_002.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_002.rego){ .md-button }
