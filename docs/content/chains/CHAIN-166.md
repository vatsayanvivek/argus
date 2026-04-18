# CHAIN-166 — Service Bus Relay without authentication

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

A WCF Service Bus Relay exposes an on-prem service to the internet without authentication. Anyone who discovers the relay URL reaches the backend service directly — bypassing corporate perimeter controls.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_004`](../rules/zt_int_004.md) | Trigger |
| [`zt_wl_002`](../rules/zt_wl_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate *.servicebus.windows.net for relay endpoints.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1595`  
**Enabled by:** [`zt_int_004`](../rules/zt_int_004.md)  

**Attacker gain:** Reachable on-prem service.


### Step 2 — Exploit the backend app directly.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_002`](../rules/zt_wl_002.md)  

**Attacker gain:** Backend compromise.


## Blast radius

| | |
|---|---|
| Initial access | Internet + enumeration. |
| Max privilege | Backend app RCE. |
| Data at risk | Backend service data |
| Services at risk | On-prem app behind the relay |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

