# cis_7_1 — Ensure endpoint protection is installed on VMs

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

VMs should have an antimalware extension installed (Microsoft Antimalware, Defender for Endpoint, etc.) to detect and prevent malicious code execution.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-3 |
| NIST 800-207 | Tenet 5 - Monitor and measure integrity and security posture |
| CIS Azure | 7.1 |
| MITRE ATT&CK Technique | T1059 |
| MITRE ATT&CK Tactic | Execution |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/vms/cis_7_1.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/vms/cis_7_1.rego){ .md-button }
