# cis_7_2 — Ensure encryption at host is enabled on VMs

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Encryption at host encrypts data stored on the VM host including temp disks and OS/data disk caches. Without it, data may be written in plaintext to shared infrastructure.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-28(1) |
| NIST 800-207 | Tenet 3 - Per-session authenticated access |
| CIS Azure | 7.2 |
| MITRE ATT&CK Technique | T1486 |
| MITRE ATT&CK Tactic | Impact |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/vms/cis_7_2.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/vms/cis_7_2.rego){ .md-button }
