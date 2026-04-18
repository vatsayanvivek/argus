# zt_data_027 — Microsoft Purview account allows public network access

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Purview is a data-catalog service that indexes metadata across your Azure data estate — including schema, lineage, and classification tags for sensitive data. Leaving publicNetworkAccess=Enabled exposes this catalog to the internet, giving adversaries a free reconnaissance API for 'where is the interesting data in this tenant'. Catalogues belong on private endpoints.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-4, SC-7 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Reconnaissance |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_027.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_027.rego){ .md-button }
