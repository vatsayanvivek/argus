# CHAIN-158 — Event Grid topic without authentication

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Event Grid topic accepts events from any source (no SAS, no AAD). An attacker publishes forged events that downstream consumers trust as legitimate — common for order-confirmation systems, payment events, and audit trails.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_003`](../rules/zt_int_003.md) | Trigger |
| [`zt_wl_002`](../rules/zt_wl_002.md) | Trigger |

## Attack walkthrough

### Step 1 — POST a forged event to the topic endpoint.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1584`  
**Enabled by:** [`zt_int_003`](../rules/zt_int_003.md)  

**Attacker gain:** Event delivered to subscribers.


### Step 2 — Process the forged event as if it were real.

**Actor:** Subscriber app  
**MITRE ATT&CK:** `T1565.001`  
**Enabled by:** [`zt_wl_002`](../rules/zt_wl_002.md)  

**Attacker gain:** Fraudulent business transactions processed.


## Blast radius

| | |
|---|---|
| Initial access | Public topic endpoint. |
| Max privilege | Event injection. |
| Data at risk | Business event integrity |
| Services at risk | Every subscriber |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

