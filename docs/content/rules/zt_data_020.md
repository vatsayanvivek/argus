# zt_data_020 — Cognitive Services account allows public network access

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Cognitive Services accounts with public network access enabled expose AI/ML endpoints to the internet. Disabling public access and using private endpoints ensures that only trusted networks can invoke inference and training APIs, preventing data exfiltration through model queries.

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

Rule defined at `policies/azure/zt/data/zt_data_020.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_020.rego){ .md-button }
