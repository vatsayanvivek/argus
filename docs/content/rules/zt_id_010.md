# zt_id_010 — No access reviews configured

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Without periodic access reviews, stale privileged access accumulates and the principle of least privilege erodes over time.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-2(7) |
| NIST 800-207 | Tenet 6 - Dynamic access policy |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_010.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_010.rego){ .md-button }
