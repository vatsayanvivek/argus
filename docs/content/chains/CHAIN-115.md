# CHAIN-115 — VNet flow log missing during incident

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

VNet NSG flow logs are not enabled. During an incident, SOC cannot see which internal IPs talked to compromised VMs. Reconstructing the lateral movement path requires host-based forensics only.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_013`](../rules/zt_net_013.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Lateral-move across VNet without leaving flow record.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.006`  
**Enabled by:** [`zt_net_013`](../rules/zt_net_013.md)  

**Attacker gain:** Silent lateral movement.


### Step 2 — Cannot enumerate affected hosts during IR.

**Actor:** SOC  
**MITRE ATT&CK:** `T1562.006`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Incomplete scoping; longer containment.


## Blast radius

| | |
|---|---|
| Initial access | Any VNet foothold. |
| Max privilege | Forensic blindness. |
| Data at risk | IR integrity |
| Services at risk | All of SOC-assisted incident response |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

