# zt_wl_017 — Function App uses outdated runtime version

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

Function Apps running outdated language runtime versions miss critical security patches and may contain known vulnerabilities exploitable for initial access. Keeping runtimes up to date reduces the attack surface.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-2 |
| NIST 800-207 | Tenet 7 - Collect information about the current state of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_017.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_017.rego){ .md-button }
