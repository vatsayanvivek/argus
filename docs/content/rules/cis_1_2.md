# cis_1_2 — Ensure MFA is enabled for all privileged users

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Identity · **Chain role:** ANCHOR

## Description

Checks that users with privileged roles such as Global Administrator or Privileged Role Administrator have MFA enabled. Privileged accounts are high value targets.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2(1) |
| NIST 800-207 | Tenet 6 - Strict authentication for privileged resources |
| CIS Azure | 1.2 |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_2.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_2.rego){ .md-button }
