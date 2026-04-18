# zt_wl_029 — VMSS has no automatic OS-image upgrade policy

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** ENABLER

## Description

VMSS instances without automaticOSUpgradePolicy.enableAutomaticOSUpgrade=true lag behind the latest image publisher's security patches. Every unpatched CVE in the base image becomes a persistent foothold across every instance the scale set spawns. Enable automatic upgrades with health-probe gating to balance availability and patch cadence.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-2 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1068 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_029.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_029.rego){ .md-button }
