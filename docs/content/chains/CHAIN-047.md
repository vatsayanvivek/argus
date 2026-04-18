# CHAIN-047 — NSG flow log evidence destruction via retention and logging gaps

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An attacker operating inside the network benefits from a triple visibility gap. First, subnets with no NSG applied generate no flow logs at all, giving the attacker network segments where their traffic is completely invisible to network forensics. Second, where NSGs do exist, flow log retention is set below 90 days, meaning evidence of the attacker's network activity is automatically purged well before most organisations detect a breach (industry average: 200+ days). Third, storage account diagnostic logging is disabled, so even if the attacker accesses storage accounts to stage or exfiltrate data, there is no record of the read/write/delete operations. The net result: the attacker can operate across unmonitored subnets, wait for flow logs to age out, and access storage with impunity - leaving the IR team with virtually no network or data-access forensics.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_013`](../rules/zt_vis_013.md) | Trigger |
| [`zt_net_019`](../rules/zt_net_019.md) | Trigger |
| [`zt_vis_016`](../rules/zt_vis_016.md) | Trigger |

## Attack walkthrough

### Step 1 — Identify subnets with no NSG applied and route lateral movement through them.

**Actor:** Attacker with internal access  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> Enumerate subnet configurations via ARM API or from within the network; subnets without an associated NSG produce no flow log records. All TCP/UDP traffic traversing these subnets is invisible to network monitoring.

**Attacker gain:** Network transit paths where all traffic is unlogged and forensically invisible.


### Step 2 — Perform reconnaissance and lateral movement across unprotected subnets to reach high-value targets.

**Actor:** Attacker with internal access  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> Port scan, credential relay, and service exploitation across the NSG-free subnets; no flow log captures source/destination IPs, ports, or byte counts for this traffic.

**Attacker gain:** Access to targets reachable from the unprotected subnets without generating any network telemetry.


### Step 3 — Access storage accounts to stage exfiltration or read sensitive blobs, knowing diagnostic logging is off.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_vis_016`](../rules/zt_vis_016.md)  

> Storage account diagnostic logging (StorageRead, StorageWrite, StorageDelete) is disabled (zt_vis_016); the attacker's blob downloads, container enumerations, and file deletions produce no log entries in the storage analytics or diagnostic settings.

**Attacker gain:** Undetectable access to storage account data - no record of what was read, written, or deleted.


### Step 4 — NSG flow log retention expires, automatically purging network evidence from monitored subnets.

**Actor:** Time (passive)  
**MITRE ATT&CK:** `T1070.003`  
**Enabled by:** [`zt_vis_013`](../rules/zt_vis_013.md)  

> Flow logs configured with retentionPolicy.days < 90 auto-delete the PT1H.json blobs from the flow log storage account. The attacker does not need to actively delete evidence - the retention policy does it for them.

**Attacker gain:** Network forensic evidence for the monitored subnets is permanently destroyed by the system's own retention policy.


## Blast radius

| | |
|---|---|
| Initial access | Any foothold on the internal network, particularly in subnets without NSGs. |
| Lateral movement | Unrestricted within NSG-free subnets; movement through monitored subnets is logged but evidence is short-lived. |
| Max privilege | Determined by the attacker's credential access; the chain amplifies stealth, not privilege. |
| Data at risk | Storage account contents (access unlogged), Any data reachable from unmonitored subnets, Forensic evidence itself (destroyed by retention) |
| Services at risk | Network Security Groups (absent), NSG Flow Logs (under-retained), Storage Accounts (unlogged) |
| Estimated scope | All subnets without NSGs plus all storage accounts without diagnostic logging |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

