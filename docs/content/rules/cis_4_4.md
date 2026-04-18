# cis_4_4 — Ensure public network access is disabled for SQL servers

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Data · **Chain role:** ANCHOR

## Description

SQL servers should not be reachable from the public internet. Public access enables credential spraying, brute force, and exfiltration from compromised workloads.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 2 - Secure communication |
| CIS Azure | 4.4 |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/database/cis_4_4.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/database/cis_4_4.rego){ .md-button }
