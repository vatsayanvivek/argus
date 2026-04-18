# CHAIN-169 — Event Grid Domain with wildcard subscription filter

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Event Grid Domain has a subscription filter using wildcard * matching. A new event with attacker-controlled fields reaches every subscriber. Combined with a subscriber that trusts field content blindly, this becomes an injection vector.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_003`](../rules/zt_int_003.md) | Trigger |
| [`zt_int_006`](../rules/zt_int_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Publish event with crafted fields.

**Actor:** Event publisher  
**MITRE ATT&CK:** `T1565.001`  
**Enabled by:** [`zt_int_003`](../rules/zt_int_003.md)  

**Attacker gain:** Event reaches every subscriber.


### Step 2 — Interprets attacker-controlled field as command parameter.

**Actor:** Unsafe subscriber  
**MITRE ATT&CK:** `T1059`  
**Enabled by:** [`zt_int_006`](../rules/zt_int_006.md)  

**Attacker gain:** Code execution in subscriber context.


## Blast radius

| | |
|---|---|
| Initial access | Publish-side compromise. |
| Max privilege | Subscriber-context RCE. |
| Data at risk | Subscriber app state |
| Services at risk | All subscribers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

