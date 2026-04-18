# zt_data_023 — Synapse workspace allows public SQL endpoint access

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Synapse workspaces with public network access enabled expose the serverless + dedicated SQL endpoints to the internet. SQL Auth or Entra ID tokens then become the only barrier. Disable public network access and restrict access to the workspace managed VNet plus explicit private endpoints.

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

Rule defined at `policies/azure/zt/data/zt_data_023.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_023.rego){ .md-button }
