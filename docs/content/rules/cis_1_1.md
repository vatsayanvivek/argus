# cis_1_1 — Ensure Multi-Factor Authentication is enabled for all non-privileged users

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ANCHOR

## Description

Checks that all enabled member users in Azure AD have MFA enabled. MFA significantly reduces the risk of credential compromise and unauthorized access.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2(1) |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | 1.1 |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_1.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_1.rego){ .md-button }
