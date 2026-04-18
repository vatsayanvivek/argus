# zt_int_007 — API Management instance has no diagnostic logs routed to Log Analytics or Event Hub

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

APIM without a diagnostic settings configuration drops audit events (gateway requests, backend failures, policy evaluations) on the floor. Incident response against an API-layer breach needs these logs. Every production APIM instance should route at least 'GatewayLogs' to Log Analytics or Event Hub.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-2, AU-12 |
| NIST 800-207 | Tenet 7 - The enterprise collects as much information as possible about the current state of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562.008 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/integration/zt_int_007.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_007.rego){ .md-button }
