# zt_wl_028 — Service Fabric cluster uses certificate thumbprint auth instead of Entra ID

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Service Fabric clusters with certificateThumbprint-based admin authentication rely on a long-lived certificate in the cluster's configuration. Rotation is painful, private-key extraction from any cluster node gives full admin. Modern Service Fabric supports 'azureActiveDirectory' authentication with group-based admin scoping — switch to it.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1), AC-2(3) |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552.004 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_028.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_028.rego){ .md-button }
