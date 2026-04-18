# zt_data_030 — NetApp volume permits NFS v3 (no Kerberos) from mount endpoints

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Data · **Chain role:** AMPLIFIER

## Description

NetApp NFS v3 volumes authenticate clients solely by source IP — there is no per-user authentication on the wire. Any workload whose NIC IP is in the export policy mounts the volume and reads every file. NFS v4.1 with Kerberos adds strong per-user auth; v3 exports should only exist for workloads that cannot support v4.1 and must be tightly restricted by subnet.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-2, AC-3 |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1005 |
| MITRE ATT&CK Tactic | Collection |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_030.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_030.rego){ .md-button }
