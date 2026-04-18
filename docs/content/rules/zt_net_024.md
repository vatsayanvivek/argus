# zt_net_024 — NAT Gateway has no idle timeout configured for long-lived connections

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Pillar:** Network · **Chain role:** ENABLER

## Description

NAT Gateway with the default idle timeout (4 minutes) cuts long-running backend connections — common for database replication, message-bus consumers, and gRPC streams — triggering reconnect storms that can mask attack traffic inside normal reconnect noise. Explicit idle-timeout configuration (30-120 minutes for stable workloads) both stabilises connections and makes anomalous connection churn easier to spot.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AU-2 |
| NIST 800-207 | Tenet 7 - The enterprise collects as much information as possible about the current state of assets |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1562 |
| MITRE ATT&CK Tactic | Defense Evasion |
| Zero-Trust Tenet | Tenet 7 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/network/zt_net_024.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/network/zt_net_024.rego){ .md-button }
