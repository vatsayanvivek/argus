# zt_id_011 — App Registration holds high-privilege Microsoft Graph permissions

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Identity · **Chain role:** ANCHOR

## Description

Application-level Microsoft Graph permissions such as RoleManagement.ReadWrite.Directory or Application.ReadWrite.All grant tenant-wide access without a user context, so a single compromised App Registration becomes a path to Global Administrator. The participating chain is CHAIN-002.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6(1) |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1550 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_011.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_011.rego){ .md-button }
