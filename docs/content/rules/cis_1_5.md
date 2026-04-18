# cis_1_5 — Ensure all subscription Owners have MFA enabled

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Identity · **Chain role:** ANCHOR

## Description

Checks that users assigned the Owner role on the subscription have MFA. Subscription Owners can modify any resource in the subscription.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2(1) |
| NIST 800-207 | Tenet 6 - Strict authentication for privileged resources |
| CIS Azure | 1.5 |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_5.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_5.rego){ .md-button }
