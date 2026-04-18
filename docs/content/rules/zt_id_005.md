# zt_id_005 — Legacy authentication protocols enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Legacy auth (IMAP/POP/SMTP/ActiveSync) bypasses modern controls including MFA and conditional access, enabling password spray attacks.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2 |
| NIST 800-207 | Tenet 2 - All communication secured |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_005.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_005.rego){ .md-button }
