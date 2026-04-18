# zt_bak_003 — Recovery Services Vault has no cross-region restore

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** ENABLER

## Description

Cross-Region Restore (CRR) replicates recovery points to the paired Azure region automatically. Without it, a region-wide outage or accidental vault deletion leaves the workload with no restore target. CRR is free for GRS-storage vaults and must be explicitly enabled — it is not the default.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CP-9, CP-10 |
| NIST 800-207 | Tenet 4 - Access to individual enterprise resources is granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1490 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/backup/zt_bak_003.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/backup/zt_bak_003.rego){ .md-button }
