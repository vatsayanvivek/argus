# zt_data_029 — MariaDB server requires SSL or uses minimum TLS version 1.2

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

MariaDB for Azure servers with ssl_enforcement disabled accept unencrypted TCP connections — credentials and query payloads travel in cleartext. Even with SSL enforcement enabled, a minimum TLS version below 1.2 permits downgrade attacks on older clients. Require SSL and minimum TLS 1.2 for every server regardless of workload sensitivity.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8, SC-13 |
| NIST 800-207 | Tenet 3 - All communication is secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1040 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_029.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_029.rego){ .md-button }
