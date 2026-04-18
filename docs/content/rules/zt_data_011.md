# zt_data_011 — Cosmos DB account allows access from all networks

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Cosmos DB accounts without virtual network filtering or with public network access enabled are reachable from any network. Restricting access to specific VNets or disabling public access limits the blast radius of credential compromise.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_011.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_011.rego){ .md-button }
