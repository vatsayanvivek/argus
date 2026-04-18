# zt_data_001 — Storage account allows public blob access

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Storage accounts with allowBlobPublicAccess=true can expose any container marked public, leading to data leaks like the infamous AWS S3 bucket exposures.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 1 - All resources considered |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_001.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_001.rego){ .md-button }
