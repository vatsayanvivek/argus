# zt_wl_021 — Defender for Containers not enabled on AKS cluster

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

AKS clusters without Microsoft Defender for Containers lack runtime threat detection, vulnerability assessment for container images, and security alerts for suspicious cluster activity. Enabling Defender provides continuous monitoring of the Kubernetes control plane and node-level workloads.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SI-4 |
| NIST 800-207 | Tenet 5 - Monitor and measure integrity and security posture of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1610 |
| MITRE ATT&CK Tactic | Execution |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_021.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_021.rego){ .md-button }
