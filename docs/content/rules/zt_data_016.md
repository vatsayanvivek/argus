# zt_data_016 — Storage account blob versioning not enabled

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Storage accounts without blob versioning cannot maintain previous versions of objects, making it impossible to recover from accidental overwrites or malicious modifications. Enabling versioning provides an immutable history of blob changes.

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

Rule defined at `policies/azure/zt/data/zt_data_016.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_016.rego){ .md-button }
