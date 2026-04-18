# CHAIN-036 — Service Bus Message Interception

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Service Bus namespaces are accessible over public endpoints, Event Hub does not enforce customer-managed key encryption for data at rest, and storage diagnostic logging is disabled. An attacker who obtains a Service Bus connection string - from a leaked configuration, a compromised application, or an overly-broad SAS policy - can connect from any IP to receive, peek, or dead-letter messages in queues and topic subscriptions. Messages flowing through the Event Hub that feeds downstream analytics are encrypted only with Microsoft-managed keys, giving the attacker confidence that a compromised storage account or export path yields readable data. With storage diagnostic logging off, the operations team has no audit trail of who accessed what, when, or how many messages were intercepted.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_019`](../rules/zt_data_019.md) | Trigger |
| [`zt_data_018`](../rules/zt_data_018.md) | Trigger |
| [`zt_vis_016`](../rules/zt_vis_016.md) | Trigger |

## Attack walkthrough

### Step 1 — Harvest a Service Bus connection string or SAS token from a compromised application, repository, or configuration store.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_019`](../rules/zt_data_019.md)  

> Connection strings containing Endpoint=sb://{namespace}.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=... found in app settings, committed code, or environment variables.

**Attacker gain:** Valid Service Bus credential with Send/Listen/Manage rights on the namespace.


### Step 2 — Connect to the public Service Bus endpoint and enumerate queues, topics, and subscriptions.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1526`  
**Enabled by:** [`zt_data_019`](../rules/zt_data_019.md)  

> ServiceBusAdministrationClient.getQueues() / getTopics() over the public endpoint; no IP firewall rule restricts the source. RootManageSharedAccessKey has Manage rights on the entire namespace.

**Attacker gain:** Full inventory of messaging entities and their message counts.


### Step 3 — Receive or peek messages from production queues, intercepting business-critical payloads.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1557`  
**Enabled by:** [`zt_data_019`](../rules/zt_data_019.md)  

> ServiceBusReceiverClient.receiveMessages() in PeekLock or ReceiveAndDelete mode; messages contain order data, PII, authentication tokens, or inter-service commands.

**Attacker gain:** Real-time interception of application message traffic including sensitive business data.


### Step 4 — Access Event Hub capture blobs in the linked storage account, reading historical message archives.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_018`](../rules/zt_data_018.md)  

> Event Hub capture writes Avro files to a storage container; without CMK, the attacker who gains storage access reads plaintext payloads. Microsoft-managed keys provide no customer-controlled revocation.

**Attacker gain:** Historical message archive spanning days or weeks of business transactions.


### Step 5 — Operate without detection because storage diagnostic logging is disabled on the capture storage account.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_016`](../rules/zt_vis_016.md)  

> StorageRead, StorageWrite, and StorageDelete diagnostic categories are not enabled; no log entry records the attacker's blob downloads from the capture container.

**Attacker gain:** Complete absence of forensic evidence for the message interception and data exfiltration.


## Blast radius

| | |
|---|---|
| Initial access | Leaked Service Bus connection string usable from any public IP. |
| Lateral movement | Service Bus namespace → Event Hub capture → linked Storage Account. |
| Max privilege | Full data-plane access to all queues, topics, subscriptions, and captured message archives in the namespace. |
| Data at risk | Real-time message payloads, Historical Event Hub capture archives, Business transaction data, Inter-service authentication tokens, Customer PII in message bodies |
| Services at risk | Azure Service Bus, Azure Event Hub, Azure Storage (capture), Downstream consumers |
| Estimated scope | All messaging entities in the namespace + capture storage |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

