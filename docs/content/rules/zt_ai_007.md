# zt_ai_007 — Bot Service endpoint lacks managed identity authentication

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Azure Bot Service instances that rely on application-password authentication to Bot Framework store the secret in the bot's web-app setting (MicrosoftAppPassword). This is a long-lived static credential. Modern Bot Service supports 'UserAssignedMSI' or 'SystemAssignedMSI' — switch to managed identity so Bot Framework token acquisition uses Entra ID, with no static secret on the bot's config.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1) |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552.001 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/ai/zt_ai_007.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/ai/zt_ai_007.rego){ .md-button }
