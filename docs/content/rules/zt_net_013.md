# zt_net_013 — Virtual network has no DDoS protection plan

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** ENABLER

## Description

Azure DDoS Protection Standard provides enhanced mitigation for volumetric, protocol, and application-layer attacks. Without a DDoS protection plan, virtual networks rely only on basic infrastructure-level protection insufficient for targeted attacks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-5 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1498 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_013.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_013.rego){ .md-button }
