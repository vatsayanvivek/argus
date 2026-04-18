# zt_vis_016 — Storage account access logging not enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** AMPLIFIER

## Description

Storage account diagnostic logs capture read, write, and delete operations. Without them, data exfiltration and tampering events cannot be detected or investigated.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-12 |
| NIST 800-207 | Tenet 5 - Integrity monitored |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1530 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_016.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_016.rego){ .md-button }
