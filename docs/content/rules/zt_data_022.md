# zt_data_022 — Databricks workspace deploys worker VMs with public IPs

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Databricks workspaces created without 'noPublicIp'=true provision each driver and worker with a public IP address. Worker nodes then initiate outbound connections to the Databricks control plane from a public endpoint, and any misconfigured NSG/firewall leaves them reachable from the internet. Secure cluster connectivity (noPublicIp=true) keeps workers on private IPs only.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_022.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_022.rego){ .md-button }
