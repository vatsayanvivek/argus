# zt_wl_024 — AKS cluster does not have Azure Policy add-on enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

AKS clusters without the Azure Policy add-on cannot enforce organisational guardrails on pod specs, resource limits, or image sources at admission time, leaving compliance enforcement to manual review.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CM-7 |
| NIST 800-207 | Tenet 6 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1610 |
| MITRE ATT&CK Tactic | Execution |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_024.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_024.rego){ .md-button }
