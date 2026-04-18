# zt_data_021 — Azure Data Factory is internet-accessible for integration runtime control plane

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Data Factory orchestrates data movement across storage accounts, databases, and external sources. An ADF with publicNetworkAccess=Enabled exposes the integration-runtime control plane to the public internet — attackers who authenticate (e.g. via leaked SAS or compromised identity) can trigger pipelines that read from and write to every linked data source. Disable public access and use a Self-Hosted IR inside the VNet.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-4, SC-7 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_021.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_021.rego){ .md-button }
