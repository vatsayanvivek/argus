# zt_data_026 — HDInsight cluster deploys with public gateway enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Network · **Chain role:** ANCHOR

## Description

HDInsight clusters with publicNetworkAccess='InboundAndOutbound' or gateway credentials managed by the cluster (not Entra ID) expose the Ambari + WebHCat endpoints to the internet, accepting basic-auth credentials. Attackers who obtain the gateway password have full cluster control. Deploy HDInsight into a VNet with privateOnly access.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-4, SC-7 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1190 |
| MITRE ATT&CK Tactic | Initial Access |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/data/zt_data_026.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/data/zt_data_026.rego){ .md-button }
