# zt_int_005 — Traffic Manager profile uses HTTP (not HTTPS) for probes

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Traffic Manager profiles with monitorProtocol=HTTP probe the endpoints over cleartext. The probe carries no auth secrets, but an attacker who can MITM the probe traffic can forge healthy responses for an unhealthy endpoint or vice versa — flipping traffic to their rogue endpoint. Use HTTPS probes for any Traffic Manager profile fronting internet-accessible services.

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

Rule defined at `policies/azure/zt/integration/zt_int_005.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_005.rego){ .md-button }
