# zt_ai_002 — Cognitive Services account relies on shared subscription keys (local auth enabled)

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

Cognitive Services accounts with local authentication enabled are authenticated via static subscription keys. Keys are long-lived shared secrets that appear in logs, CI variables, and client-side code — any leak gives durable access. Entra ID auth with managed identities eliminates the shared-secret attack surface.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1), AC-2(3) |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552.001 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/ai/zt_ai_002.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/ai/zt_ai_002.rego){ .md-button }
