# cis_1_4 — Ensure no custom subscription owner roles are created

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

Custom roles with Owner privileges bypass standard controls and can be used to obscure privilege escalation paths.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6(1) |
| NIST 800-207 | Tenet 6 - Least privilege role assignment |
| CIS Azure | 1.4 |
| MITRE ATT&CK Technique | T1098 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_4.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_4.rego){ .md-button }
