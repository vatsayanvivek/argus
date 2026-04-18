# CHAIN-043 — Firewall threat intel bypass to persistent C2 channel

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Firewall is deployed but its threat intelligence mode is set to 'Alert only' instead of 'Deny', meaning known-malicious IPs and domains generate a log entry but traffic is allowed through. An attacker who has initial access to any workload behind the firewall can establish a command-and-control channel to known bad infrastructure and the firewall will wave it through with a warning nobody reads. Meanwhile, the NSG on the workload subnets permits all outbound traffic (0.0.0.0/0), so even traffic that bypasses the firewall route has no secondary control. The attacker exfiltrates data freely over HTTPS to a threat-intel-listed domain. When the SOC eventually investigates, NSG flow logs have a retention of less than 90 days, so historical evidence of the C2 channel and exfiltration volume has already been purged - the investigation hits a dead end.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_012`](../rules/zt_net_012.md) | Trigger |
| [`zt_net_018`](../rules/zt_net_018.md) | Trigger |
| [`zt_vis_013`](../rules/zt_vis_013.md) | Trigger |

## Attack walkthrough

### Step 1 — Establish an outbound C2 channel to a known-malicious domain or IP address.

**Actor:** Attacker with workload access  
**MITRE ATT&CK:** `T1071.001`  
**Enabled by:** [`zt_net_012`](../rules/zt_net_012.md)  

> Implant beacons to a C2 framework (Cobalt Strike, Sliver) over HTTPS/443 to an IP listed in Microsoft's threat intelligence feed; Azure Firewall logs ThreatIntel=Alert but forwards the traffic.

**Attacker gain:** Persistent, bidirectional command-and-control channel through the firewall.


### Step 2 — Confirm unrestricted outbound connectivity through the NSG for high-bandwidth exfiltration.

**Actor:** Attacker with C2  
**MITRE ATT&CK:** `T1048.001`  
**Enabled by:** [`zt_net_018`](../rules/zt_net_018.md)  

> NSG effective rules show outbound Allow to 0.0.0.0/0 on all ports; no service endpoints or Private Link force traffic through controlled paths; the attacker can reach any internet destination on any port.

**Attacker gain:** Unlimited outbound bandwidth with no port or destination restrictions for data exfiltration.


### Step 3 — Stage and exfiltrate sensitive data over the established C2 channel using encrypted HTTPS.

**Actor:** Attacker with C2  
**MITRE ATT&CK:** `T1041`  
**Enabled by:** [`zt_net_018`](../rules/zt_net_018.md)  

> Compress and encrypt target data, then exfil via HTTPS POST to the C2 endpoint. TLS encryption prevents DPI even if the firewall were inspecting payloads. Volume is limited only by the VM's NIC bandwidth.

**Attacker gain:** Bulk exfiltration of sensitive data to attacker infrastructure with no volume cap.


### Step 4 — Wait for NSG flow log retention to expire, destroying network evidence of the C2 and exfiltration.

**Actor:** Attacker (anti-forensics)  
**MITRE ATT&CK:** `T1070.003`  
**Enabled by:** [`zt_vis_013`](../rules/zt_vis_013.md)  

> NSG flow logs are configured with retention less than 90 days (zt_vis_013). After the retention window passes, the storage account auto-deletes the PT1H.json flow log blobs. The firewall threat intel alert log may persist longer but shows only 'Alert' actions, not deny - confirming the traffic was allowed.

**Attacker gain:** Forensic evidence of C2 traffic volume, destination IPs, and session durations is permanently destroyed.


### Step 5 — Investigate belatedly and find evidence gaps that prevent scope determination.

**Actor:** SOC / IR team  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_013`](../rules/zt_vis_013.md)  

> Firewall logs show ThreatIntel alerts but no deny; NSG flow logs for the period have been purged; the investigation cannot determine exfiltration volume, full list of C2 destinations, or which workloads communicated externally.

**Attacker gain:** The attacker's operational history is unrecoverable, forcing the organisation to assume worst-case breach scope.


## Blast radius

| | |
|---|---|
| Initial access | Any compromised workload behind the Azure Firewall with outbound internet access. |
| Lateral movement | C2 channel enables the attacker to proxy tools inbound, pivot to other workloads, and stage further attacks from within the network. |
| Max privilege | Depends on initial compromise; the chain enables persistent C2 and evidence destruction regardless of privilege level. |
| Data at risk | Any data accessible to the compromised workload, Credentials cached on the host, Data from lateral movement targets |
| Services at risk | Azure Firewall (misconfigured), NSG-protected subnets, All workloads routable through the firewall |
| Estimated scope | All subnets routed through the firewall with permissive NSG outbound rules |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

