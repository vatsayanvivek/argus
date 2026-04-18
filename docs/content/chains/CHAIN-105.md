# CHAIN-105 — NAT gateway with outbound any + data exfil channel

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

NAT gateway allows outbound to any destination and the VNet has no egress monitoring. A compromised VM can exfiltrate to attacker DNS or HTTP servers without triggering any network alert.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_024`](../rules/zt_net_024.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — DNS-tunnel data to attacker.com via NAT gateway.

**Actor:** Compromised VM  
**MITRE ATT&CK:** `T1048.003`  
**Enabled by:** [`zt_net_024`](../rules/zt_net_024.md)  

**Attacker gain:** Data leaving via unmonitored egress.


### Step 2 — Reassemble tunnelled data at C2 server.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1041`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Slow-drip exfiltration, undetected.


## Blast radius

| | |
|---|---|
| Initial access | Any VM compromise. |
| Max privilege | Covert exfil channel. |
| Data at risk | Anything reachable by VM |
| Services at risk | Any private resource the VM can read |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

