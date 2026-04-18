# zt_net_018 — NSG allows all outbound traffic to the Internet

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Network Security Groups that permit unrestricted outbound traffic to the Internet enable data exfiltration and command-and-control communication. Outbound traffic should be restricted to known destinations and ports.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1048 |
| MITRE ATT&CK Tactic | Exfiltration |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_018.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_018.rego){ .md-button }
