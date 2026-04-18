# zt_net_023 — ExpressRoute circuit does not use MACsec encryption

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Pillar:** Network · **Chain role:** AMPLIFIER

## Description

ExpressRoute circuits without MACsec (configured via adminState='Enabled' on linkFeatures.macSec) carry customer traffic between Microsoft's edge and the on-prem provider without link-layer encryption. Any physical-layer tap on the shared fibre between the meet-me point and your provider edge reads the traffic. MACsec is free and available on ExpressRoute Direct — enable it.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | SC-8 |
| NIST 800-207 | Tenet 3 - All communication is secured regardless of network location |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1040 |
| MITRE ATT&CK Tactic | Credential Access |
| Zero-Trust Tenet | Tenet 3 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_023.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_023.rego){ .md-button }
