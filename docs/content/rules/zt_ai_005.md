# zt_ai_005 — Azure ML Workspace uses the default Microsoft-managed key

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

ML Workspaces store training datasets, hyperparameters, and model weights in the associated Storage + Key Vault. By default this encryption uses Microsoft-managed keys. For regulated training data (patient records, financial transactions, proprietary corpora), a customer-managed key via the workspace's encryption property is required to satisfy the HIPAA/SOC 2 auditor that the tenant, not Microsoft, controls key material.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-12, SC-28 |
| NIST 800-207 | Tenet 4 - Access to individual enterprise resources is granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/ai/zt_ai_005.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/ai/zt_ai_005.rego){ .md-button }
