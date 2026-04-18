# zt_bak_005 — Site Recovery replication policy uses inadequate RPO

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Azure Site Recovery replication policies with an RPO (recovery point objective) of 30 minutes or worse leave too much time between replication snapshots — a ransomware or data-corruption event discovered 20 minutes after impact may not have a clean recovery point within the RPO window. For production workloads, RPO <= 15 minutes is the baseline; mission-critical should target 5 minutes.

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

Rule defined at `policies/azure/zt/backup/zt_bak_005.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/backup/zt_bak_005.rego){ .md-button }
