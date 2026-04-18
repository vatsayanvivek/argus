# CHAIN-016 — No JIT open ports no alert to persistent backdoor

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Just-in-Time VM access is not enabled, NSGs allow management ports from the internet permanently, and there are no alerts on NSG rule additions. An attacker who gains initial access can add a new NSG rule to open any port they choose - creating a durable backdoor - and the platform never fires an alert. The victim has replaced a time-bound access gate with a permanent freeway.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_010`](../rules/zt_vis_010.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |
| [`zt_vis_008`](../rules/zt_vis_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Access an internet-exposed management port with stolen credentials or CVE exploitation.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

> NSG rule allows *:22 or *:3389 inbound; JIT would have required approval and time-bounded it but is not enabled.

**Attacker gain:** Initial access on the VM.


### Step 2 — Add a new NSG rule opening an additional unusual port for a persistent callback channel.

**Actor:** Attacker on VM  
**MITRE ATT&CK:** `T1133`  
**Enabled by:** [`zt_vis_010`](../rules/zt_vis_010.md)  

> Using the host's managed identity (or compromised admin) call az network nsg rule create --destination-port-ranges 12345.

**Attacker gain:** Durable ingress on an obscure port that survives rotation of the original credential.


### Step 3 — Operate without alerting on NSG changes.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_vis_008`](../rules/zt_vis_008.md)  

> No alert rule on Microsoft.Network/networkSecurityGroups/securityRules/write; no policy denies the operation; change blends into noise.

**Attacker gain:** Undetected persistence for weeks or months.


## Blast radius

| | |
|---|---|
| Initial access | Internet-exposed management port. |
| Lateral movement | Persistent backdoor → whatever the backdoored VM can reach. |
| Max privilege | Persistent VM control + ability to mutate NSGs. |
| Data at risk | Data reachable from the VM, Credentials cached on the VM |
| Services at risk | Compute, Network, Any internal service reachable from the VM |
| Estimated scope | VM and its lateral reachable set over time |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

