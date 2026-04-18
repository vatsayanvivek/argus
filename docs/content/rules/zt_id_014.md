# zt_id_014 — No authentication strength policy enforced for administrators

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** ENABLER

## Description

Authentication strength policies ensure administrators use phishing-resistant credentials such as FIDO2 or certificate-based authentication. Without an authentication strength requirement in Conditional Access, admins may authenticate with weaker methods vulnerable to token theft.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2(6) |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1556 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_014.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_014.rego){ .md-button }
