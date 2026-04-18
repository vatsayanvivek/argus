# CHAIN-112 — NSG priority collision allows unintended traffic

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Two NSG rules target the same port but with different access decisions; the lower-priority Allow comes first due to rule-number ordering. The admin believes a Deny is in effect but the Allow fires. The visible effect is an 'open' port that shouldn't be.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_010`](../rules/zt_net_010.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Port-scan discovers 'blocked' port is actually open.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1595.001`  
**Enabled by:** [`zt_net_010`](../rules/zt_net_010.md)  

**Attacker gain:** Unexpected reachability.


### Step 2 — Exploit the reachable service.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** Lateral foothold.


## Blast radius

| | |
|---|---|
| Initial access | Network-visible port scan. |
| Max privilege | Whatever the service exposes. |
| Data at risk | Service data |
| Services at risk | Service behind the 'blocked' port |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

