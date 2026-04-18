# cis_1_8 — Ensure legacy authentication protocols are blocked

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Legacy authentication (IMAP, POP, SMTP basic auth, older Office clients) does not support MFA and is the primary vector for password spray attacks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | 1.8 |
| MITRE ATT&CK Technique | T1110.003 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/identity/cis_1_8.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/identity/cis_1_8.rego){ .md-button }
