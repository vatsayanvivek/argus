# cis_6_1 — Ensure SSH (port 22) is not exposed to the internet

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Network · **Chain role:** ANCHOR

## Description

NSG inbound rules must not allow TCP port 22 from '*' or '0.0.0.0/0'. Exposed SSH is the #1 cause of compromise for Azure Linux VMs.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-7 |
| NIST 800-207 | Tenet 2 - Secure communication regardless of network location |
| CIS Azure | 6.1 |
| MITRE ATT&CK Technique | T1021.004 |
| MITRE ATT&CK Tactic | Lateral Movement |
| Zero-Trust Tenet | Tenet 2 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/networking/cis_6_1.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/networking/cis_6_1.rego){ .md-button }
