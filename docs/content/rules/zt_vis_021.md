# zt_vis_021 — No Activity Log alert for role assignment creation at subscription scope

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

Without an Activity Log alert on 'Microsoft.Authorization/roleAssignments/write', nobody gets paged when an attacker with Owner or UAA grants themselves (or a backdoor SP) a new role. This is the single highest-value alert in any Azure environment — a true positive always means privilege movement is happening. If it isn't wired up, RBAC drift goes unnoticed until the next audit.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-6, SI-4 |
| NIST 800-207 | Tenet 7 - The enterprise collects as much information as possible about the current state of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1098.003 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_021.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_021.rego){ .md-button }
