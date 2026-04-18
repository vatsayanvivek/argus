# zt_vis_022 — No Activity Log alert for Key Vault 'listKeys' or 'listSecrets' operations

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Visibility · **Chain role:** ENABLER

## Description

An attacker with secrets-access permission on any Key Vault in the subscription can quietly enumerate and exfiltrate every secret via listKeys/listSecrets. Without an alert, these bulk-enumeration calls are indistinguishable from legitimate provisioning traffic. Alert on them targeting subscription scope + a pager action group.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-6, SI-4 |
| NIST 800-207 | Tenet 7 - The enterprise collects as much information as possible about the current state of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552.007 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/visibility/zt_vis_022.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/visibility/zt_vis_022.rego){ .md-button }
