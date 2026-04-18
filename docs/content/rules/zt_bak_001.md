# zt_bak_001 — Recovery Services Vault lacks immutability protection

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Data · **Chain role:** ENABLER

## Description

Recovery Services Vaults without immutability enabled allow operators with Backup Contributor (or higher) privilege to delete or mutate recovery points. In a ransomware scenario the attacker's first move after privilege escalation is to destroy backups so the victim has no choice but to pay. Immutable vaults refuse recovery-point deletion for the retention period, eliminating this attack step.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9, SI-7 |
| NIST 800-207 | Tenet 4 - Access to individual enterprise resources is granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1490 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/backup/zt_bak_001.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/backup/zt_bak_001.rego){ .md-button }
