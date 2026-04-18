# zt_int_003 — Event Grid / Service Bus / Event Hub namespace allows local auth (SAS keys)

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

Messaging namespaces (Event Grid, Service Bus, Event Hub) with local authentication enabled accept SAS-key authentication. SAS keys are static, long-lived, and commonly end up in environment variables, CI secrets, and config repos. Disabling local auth forces every publisher and subscriber to use Entra ID tokens via managed identity, eliminating the shared-secret risk class.

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

Rule defined at `policies/azure/zt/integration/zt_int_003.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_003.rego){ .md-button }
