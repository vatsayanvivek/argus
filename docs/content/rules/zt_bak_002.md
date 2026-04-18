# zt_bak_002 — Recovery Services Vault has soft delete disabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Without soft delete, a Backup operator (or attacker who compromised one) can permanently delete recovery points in a single API call. Soft delete gives 14 days to recover from accidental or malicious deletion. It is free, has no performance cost, and the default should never be disabled except for development vaults.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9 |
| NIST 800-207 | Tenet 4 - Access to individual enterprise resources is granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1490 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/backup/zt_bak_002.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/backup/zt_bak_002.rego){ .md-button }
