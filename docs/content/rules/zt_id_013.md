# zt_id_013 — Conditional Access policies do not define named locations

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Named locations allow Conditional Access policies to differentiate requests by geography or IP range. Without named locations, policies cannot enforce location-based restrictions, weakening the Zero Trust verification posture.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-2(12) |
| NIST 800-207 | Tenet 3 - Access granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_013.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_013.rego){ .md-button }
