# zt_ai_004 — Azure ML Workspace is internet-exposed

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

An Azure Machine Learning workspace with public network access hosts training compute, model registries, and datasets reachable from the internet. Adversaries can enumerate model endpoints, attempt to pull training data via misconfigured registries, or issue control-plane calls that manipulate training jobs. ML workspaces should live behind a managed virtual network or private endpoint.

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

Rule defined at `policies/azure/zt/ai/zt_ai_004.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/ai/zt_ai_004.rego){ .md-button }
