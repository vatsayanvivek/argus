# zt_wl_022 — AKS cluster does not use Key Vault CSI driver for secrets

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

AKS clusters without the Azure Key Vault Secrets Provider add-on store secrets as Kubernetes Secrets, which are base64-encoded but not encrypted at the application layer. Using the Key Vault CSI driver ensures secrets are fetched directly from Key Vault and never persisted in etcd.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-12 |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_022.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_022.rego){ .md-button }
