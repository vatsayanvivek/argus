# zt_data_025 — Stream Analytics job lacks customer-managed key encryption

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Stream Analytics jobs buffer event-stream data on Microsoft-managed disks during processing. Without a customer-managed key configured in the job's identity + keyVaultProperties, that buffer is encrypted with Microsoft keys by default. For regulated streams (payment events, health telemetry, financial trades), the SOC 2 + HIPAA + PCI auditors require the customer to own the encryption key material.

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

Rule defined at `policies/azure/zt/data/zt_data_025.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_025.rego){ .md-button }
