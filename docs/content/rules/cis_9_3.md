# cis_9_3 — Ensure App Service remote debugging is disabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ENABLER

## Description

Remote debugging allows attaching a debugger from outside Azure. Production App Services must not have remote debugging enabled.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | CM-7 |
| NIST 800-207 | Tenet 5 - Monitor posture |
| CIS Azure | 9.3 |
| MITRE ATT&CK Technique | T1059 |
| MITRE ATT&CK Tactic | Execution |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, cis-azure-2.0, nist-800-53 |

## Source

Rule defined at `policies/azure/cis/appservice/cis_9_3.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/cis/appservice/cis_9_3.rego){ .md-button }
