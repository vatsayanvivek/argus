# zt_id_009 — External collaboration unrestricted

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Unrestricted guest permissions or invite settings allow external identities to enumerate directory objects and potentially escalate via consent attacks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-3 |
| NIST 800-207 | Tenet 4 - Access determined by dynamic policy |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1199 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 4 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_009.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_009.rego){ .md-button }
