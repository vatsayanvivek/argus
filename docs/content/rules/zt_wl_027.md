# zt_wl_027 — Virtual Machine Scale Set does not use managed identity

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

VMSS instances without a managed identity must authenticate to other Azure services using either (a) embedded secrets in VM extensions, or (b) a static service principal whose credentials need rotating. Managed identity removes both problems: the instance metadata service delivers a fresh token per instance per session. Every VMSS that calls Azure APIs should have SystemAssigned identity.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1), IA-3 |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_027.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_027.rego){ .md-button }
