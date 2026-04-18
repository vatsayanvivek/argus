# zt_id_008 — Service Principal holds Owner/Contributor at subscription scope

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

Service principals with Owner or Contributor rights at subscription scope are high-value credentials whose compromise leads to full tenant control.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-6(1) |
| NIST 800-207 | Tenet 6 - Dynamic access policy and least privilege |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Privilege Escalation |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/identity/zt_id_008.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/identity/zt_id_008.rego){ .md-button }
