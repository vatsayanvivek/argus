# zt_wl_025 — Container App is externally-ingressed and allows insecure HTTP

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Container Apps with external ingress reach the public internet via Azure's shared ingress. When allowInsecureConnections is true, HTTP-without-TLS is accepted, enabling downgrade attacks and cleartext credential capture. For any external-facing Container App, TLS must be mandatory.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8, SC-13 |
| NIST 800-207 | Tenet 3 - All communication is secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1557 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_025.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_025.rego){ .md-button }
