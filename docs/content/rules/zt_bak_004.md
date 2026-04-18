# zt_bak_004 — Recovery Services backup policy has retention below 7 days

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Backup policies with shorter retention than 7 days cannot recover a workload from a malicious action that went unnoticed for more than the retention window. Ransomware groups routinely stay dormant for 3-5 days before encryption to ensure backups of the clean state are gone. 7-day retention is the minimum floor; regulated workloads need 30+ days.

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

Rule defined at `policies/azure/zt/backup/zt_bak_004.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/backup/zt_bak_004.rego){ .md-button }
