# zt_wl_001 — Virtual Machine has no managed identity

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

VMs without a system or user-assigned managed identity must store credentials locally, creating credential sprawl and privilege escalation opportunities.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_001.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_001.rego){ .md-button }
