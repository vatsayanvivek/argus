# zt_wl_007 — AKS cluster allows privileged containers

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

AKS clusters without Azure Policy or pod security enforcement can run privileged containers that break out to the node and escalate to cluster admin.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1611 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_007.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_007.rego){ .md-button }
