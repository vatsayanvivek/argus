# zt_int_006 — Front Door profile accepts TLS below 1.2

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

Front Door profiles with minimumTlsVersion below 1.2 negotiate weak ciphers with older clients, giving MITM attackers downgrade-attack opportunity against every origin behind the profile. Front Door is a public-internet accelerator — the TLS floor must be 1.2.

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

Rule defined at `policies/azure/zt/integration/zt_int_006.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/integration/zt_int_006.rego){ .md-button }
