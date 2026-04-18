# zt_data_013 — Storage account soft delete not enabled for blobs

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Storage accounts without blob soft delete cannot recover accidentally or maliciously deleted data. Enabling soft delete provides a retention window during which deleted blobs can be restored, mitigating ransomware and insider threat scenarios.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9 |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1485 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_013.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_013.rego){ .md-button }
