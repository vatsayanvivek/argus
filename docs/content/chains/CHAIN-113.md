# CHAIN-113 — Subnet without NSG and with a publicly-reachable VM

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A subnet has no NSG attached and contains a VM with a public IP. Azure network security boils down to 'the VM's OS firewall', which is often Windows Firewall exclusions or permissive Linux iptables. Any service the VM runs is internet-reachable.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_011`](../rules/zt_net_011.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Port-scan the VM's public IP; find an exposed service.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1595.001`  
**Enabled by:** [`zt_net_011`](../rules/zt_net_011.md)  

**Attacker gain:** Service discovery.


### Step 2 — Exploit the service or brute-force its auth.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** VM compromise.


## Blast radius

| | |
|---|---|
| Initial access | Internet scan. |
| Max privilege | Full VM RCE. |
| Data at risk | VM filesystem, MI token |
| Services at risk | The VM + anything its MI can reach |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

