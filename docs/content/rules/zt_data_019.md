# zt_data_019 — Service Bus namespace allows public network access

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Service Bus namespaces with public network access enabled are reachable from the internet, allowing any authenticated or unauthenticated caller to attempt connections. Disabling public access and using private endpoints restricts the attack surface to trusted networks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - Monitor and measure integrity and security posture of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_019.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_019.rego){ .md-button }
