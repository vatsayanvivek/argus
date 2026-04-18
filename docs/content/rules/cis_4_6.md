# cis_4_6 — SQL Server uses Azure AD-only authentication

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

SQL Servers that allow local SQL authentication alongside Azure AD are vulnerable to password-based attacks. Azure AD-only authentication enforces MFA, conditional access, and centralized identity governance.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2 |
| NIST 800-207 | — |
| CIS Azure | 4.6 |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | — |
| Framework tags | cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/database/cis_4_6.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/database/cis_4_6.rego){ .md-button }
