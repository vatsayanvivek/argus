# cis_7_4 — Ensure vulnerability assessment is enabled on VMs

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

VMs should have a vulnerability assessment solution installed (Qualys, Defender for Endpoint vuln mgmt, etc.) to continuously enumerate CVE exposure.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | RA-5 |
| NIST 800-207 | Tenet 7 - Collect posture information |
| CIS Azure | 7.4 |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/vms/cis_7_4.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/vms/cis_7_4.rego){ .md-button }
