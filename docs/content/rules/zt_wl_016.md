# zt_wl_016 — AKS cluster does not enforce pod security standards

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** AMPLIFIER

## Description

AKS clusters without pod security policies or the Azure Policy add-on allow containers to run with elevated privileges, host networking, or other dangerous capabilities. Enforcing pod security standards limits container escape and lateral movement.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CM-7 |
| NIST 800-207 | Tenet 7 - Collect information about the current state of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1610 |
| MITRE ATT&CK Tactic | Execution |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_016.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_016.rego){ .md-button }
