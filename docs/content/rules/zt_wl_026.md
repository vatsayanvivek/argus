# zt_wl_026 — App Configuration store allows local authentication (access keys)

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Identity · **Chain role:** AMPLIFIER

## Description

App Configuration stores with local authentication enabled accept static access keys — long-lived shared secrets that end up in CI variables, config repos, and logs. Every key leak gives durable read/write access to every feature flag + config value in the store. Disable local auth and force callers to use Entra ID + managed identity.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | IA-5(1) |
| NIST 800-207 | Tenet 6 - All resource authentication is dynamic and strictly enforced |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1552.001 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 6 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/workload/zt_wl_026.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/workload/zt_wl_026.rego){ .md-button }
