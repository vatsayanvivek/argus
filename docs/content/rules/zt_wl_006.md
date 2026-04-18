# zt_wl_006 — VM missing vulnerability assessment extension

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** ENABLER

## Description

VMs without the Qualys or Defender vulnerability assessment extension have no visibility into unpatched CVEs and known vulnerable software.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | RA-5 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_006.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_006.rego){ .md-button }
