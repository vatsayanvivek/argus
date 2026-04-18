# zt_data_028 — Synapse Dedicated SQL Pool has no Transparent Data Encryption

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Synapse Dedicated SQL pools contain warehouse data that commonly includes customer PII, transaction history, and analytic aggregates. Without TDE enabled, the on-disk storage for the pool is unencrypted — any stolen database-file backup is readable in cleartext. TDE is free, has zero performance cost on modern storage, and is expected by every audit.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28(1) |
| NIST 800-207 | Tenet 4 - Access to individual enterprise resources is granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1005 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_028.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_028.rego){ .md-button }
