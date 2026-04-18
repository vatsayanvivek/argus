# zt_ai_006 — Azure ML compute cluster does not enforce SSH to private network

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

ML compute clusters with remoteLoginPortPublicAccess='Enabled' expose an SSH endpoint on every worker directly to the public internet. Even with strong SSH credentials, this is an unnecessary attack surface for training workloads that normally run autonomously. Keep SSH private and rely on private-endpoint jump-host access if human debugging is needed.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-17, SC-7 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1021.004 |
| MITRE ATT&CK Tactic | Lateral Movement |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/ai/zt_ai_006.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/ai/zt_ai_006.rego){ .md-button }
