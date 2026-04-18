# CHAIN-168 — Service Bus topic with over-privileged SAS

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Service Bus topic distributes events to dozens of subscribers. A single SAS with Manage + Send + Listen is used by every producer and consumer. Any compromise grants full control over the topic.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_004`](../rules/zt_int_004.md) | Trigger |
| [`zt_int_002`](../rules/zt_int_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Obtain the shared SAS from any one consumer.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_int_004`](../rules/zt_int_004.md)  

**Attacker gain:** Full topic control.


### Step 2 — Delete subscriptions or inject poisoned events.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1565.001`  
**Enabled by:** [`zt_int_002`](../rules/zt_int_002.md)  

**Attacker gain:** Disruption + integrity compromise.


## Blast radius

| | |
|---|---|
| Initial access | Any consumer compromise. |
| Max privilege | Topic administration. |
| Data at risk | Topic integrity |
| Services at risk | Every subscriber |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

