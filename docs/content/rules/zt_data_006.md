# zt_data_006 — Storage account encryption-at-rest key source not configured

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Storage accounts without an explicit encryption keySource rely on opaque defaults; explicit configuration (Microsoft.Storage or Microsoft.Keyvault) is required for auditability.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1486 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_006.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_006.rego){ .md-button }
