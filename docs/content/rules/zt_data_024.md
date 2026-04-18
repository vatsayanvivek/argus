# zt_data_024 — Redis Cache uses TLS < 1.2 or allows non-SSL port

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

Redis Cache with minimumTlsVersion below 1.2 or enableNonSslPort=true accepts traffic that downgrade-attackers can intercept. TLS 1.2+ and SSL-only mode are the baseline for every cache containing session tokens, cached PII, or precomputed authorization state.

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

Rule defined at `policies/azure/zt/data/zt_data_024.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_024.rego){ .md-button }
