# zt_id_019 — Token lifetime exceeds secure threshold

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

Access token lifetimes exceeding 60 minutes widen the window for token theft and replay attacks. Shorter lifetimes force re-evaluation of Conditional Access policies and reduce exposure from compromised tokens.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-12 |
| NIST 800-207 | Tenet 3 - Access granted on a per-session basis |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1550.001 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_019.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_019.rego){ .md-button }
