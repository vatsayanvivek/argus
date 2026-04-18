# cis_3_3 — Ensure public blob access is disabled on storage accounts

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Data · **Chain role:** ANCHOR

## Description

Storage accounts with allowBlobPublicAccess=true permit anonymous reads of any container configured as Blob or Container public access. This is a primary cause of cloud data breaches.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 3 - Per-session authenticated access |
| CIS Azure | 3.3 |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/storage/cis_3_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/storage/cis_3_3.rego){ .md-button }
