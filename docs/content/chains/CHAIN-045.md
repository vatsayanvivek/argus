# CHAIN-045 — Event stream hijack via public messaging services

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

Event Hub namespaces are encrypted with Microsoft-managed keys only (no customer-managed key), meaning Microsoft - or anyone who compromises the platform key hierarchy - can decrypt the data at rest. More critically, Service Bus namespaces are accessible from public networks, exposing queue and topic endpoints to the internet. Without Azure Firewall deployed to provide network-level inspection and egress control, there is no choke point to detect or block an attacker who enumerates the publicly-reachable Service Bus endpoint, obtains a valid SAS token (from a leaked connection string or a compromised workload), and begins reading, injecting, or replaying messages in the event stream. The attacker can silently eavesdrop on business events, inject malicious commands into processing pipelines, or replay financial transactions.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_018`](../rules/zt_data_018.md) | Trigger |
| [`zt_data_019`](../rules/zt_data_019.md) | Trigger |
| [`zt_net_011`](../rules/zt_net_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover publicly accessible Service Bus namespace endpoints via DNS enumeration.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1595.002`  
**Enabled by:** [`zt_data_019`](../rules/zt_data_019.md)  

> Enumerate *.servicebus.windows.net via DNS brute-force or certificate transparency logs; confirm TCP/443 (AMQP-over-WebSocket) and TCP/5671 (AMQP) are reachable from the internet.

**Attacker gain:** Confirmed list of internet-reachable Service Bus namespaces belonging to the target.


### Step 2 — Obtain a valid SAS token or connection string from a compromised workload or leaked configuration.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_net_011`](../rules/zt_net_011.md)  

> Harvest connection strings from GitHub commits, Docker image layers, or environment variables on a compromised app service. SAS tokens often have long validity periods (years) and are not rotated.

**Attacker gain:** Valid authentication credentials for the Service Bus namespace with Send/Listen/Manage rights.


### Step 3 — Eavesdrop on message queues and topics to intercept business-critical event data.

**Actor:** Attacker with SAS token  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_data_019`](../rules/zt_data_019.md)  

> Use Service Bus Explorer or custom AMQP client to peek/receive messages from queues and subscriptions; messages may contain PII, financial transactions, or internal commands.

**Attacker gain:** Real-time visibility into all event data flowing through the compromised namespace.


### Step 4 — Inject malicious messages into processing queues to manipulate downstream business logic.

**Actor:** Attacker with SAS token  
**MITRE ATT&CK:** `T1565.002`  
**Enabled by:** [`zt_data_018`](../rules/zt_data_018.md)  

> Send crafted messages to queues consumed by order processing, payment, or workflow automation systems; lack of message signing means consumers cannot distinguish legitimate from injected messages.

**Attacker gain:** Ability to trigger arbitrary business actions: fraudulent transactions, workflow manipulation, or denial of service via poison messages.


## Blast radius

| | |
|---|---|
| Initial access | Publicly accessible Service Bus namespace with a leaked or stolen SAS token. |
| Lateral movement | Message injection can trigger downstream services to take actions that extend the attacker's reach (e.g., provisioning resources, modifying data). |
| Max privilege | Full read/write/manage access to the messaging namespace; downstream impact depends on what consumers do with the messages. |
| Data at risk | Event stream payloads (PII, financial data, internal commands), Event Hub capture data at rest (platform-key only), Downstream data stores populated by stream consumers |
| Services at risk | Event Hubs, Service Bus, Downstream consumers (Functions, Logic Apps, custom processors) |
| Estimated scope | All queues and topics in the affected namespaces |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

