# zt_wl_030 — Container App Environment is zone-redundant but has no managed identity

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Container App Environments hosting production workloads should authenticate to dependent services (Key Vault, Storage, ACR) via managed identity, not static secrets in env vars. An Environment without a UserAssigned identity forces every Container App inside it to either bake secrets into manifests or fetch them from a shared SAS token — both fail-open designs.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1) |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_030.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_030.rego){ .md-button }
