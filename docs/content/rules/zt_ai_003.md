# zt_ai_003 — Cognitive Services account lacks customer-managed key encryption

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Cognitive Services accounts default to Microsoft-managed keys for encryption-at-rest. For workloads processing regulated data (PHI, PII, payment data, proprietary content), customer-managed keys (CMK) stored in Key Vault are required by SOC 2, HIPAA, and PCI for the auditor to confirm the customer, not Microsoft, controls decryption.

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

Rule defined at `policies/azure/zt/ai/zt_ai_003.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/ai/zt_ai_003.rego){ .md-button }
