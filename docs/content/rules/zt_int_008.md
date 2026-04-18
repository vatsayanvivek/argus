# zt_int_008 — API Management is not deployed in internal-VNet mode for sensitive backends

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** ENABLER

## Description

APIM instances in External VNet mode terminate the public-gateway at the Azure edge, then reach private backends. Internal VNet mode puts the whole gateway inside the customer VNet — the public endpoint is absent, callers must come via Application Gateway / Front Door. For APIM fronting regulated workloads, Internal VNet is the defense-in-depth posture.

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

Rule defined at `policies/azure/zt/integration/zt_int_008.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_008.rego){ .md-button }
