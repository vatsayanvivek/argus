# zt_wl_009 — VM missing antimalware extension

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Windows VMs should run the Microsoft Antimalware or Defender for Endpoint extension; Linux VMs should run Defender for Servers.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-3 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1059 |
| MITRE ATT&CK Tactic | Execution |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_009.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_009.rego){ .md-button }
