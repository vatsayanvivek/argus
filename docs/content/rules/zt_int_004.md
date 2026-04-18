# zt_int_004 — Logic App workflow accepts HTTP trigger from anywhere with no IP restriction

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ANCHOR

## Description

Logic Apps (Standard or Consumption) with an HTTP trigger are publicly callable by anyone with the URL. The SAS signature in the URL is the only authentication — URL leaks = trivial abuse. Restrict inbound IPs via the workflow's accessControl.triggers block, or put the workflow behind API Management with Entra-ID-authenticated calls.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-4, AC-3(5) |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/integration/zt_int_004.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_004.rego){ .md-button }
