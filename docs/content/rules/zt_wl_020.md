# zt_wl_020 — Virtual Machine disk encryption not enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Virtual Machines without OS disk encryption leave data at rest unprotected. An attacker who gains access to the underlying storage or snapshots can read sensitive data directly from the disk without needing OS-level credentials.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28(1) |
| NIST 800-207 | Tenet 1 - All data sources and computing services are considered resources |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1005 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 1 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_020.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_020.rego){ .md-button }
