# CHAIN-085 — Redis cache exposed without AUTH

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure Cache for Redis has public network access enabled, and the developer enabled non-SSL port 6379 or disabled AUTH. Redis is internet-reachable, no auth required. Any attacker can KEYS *, read session tokens, and impersonate users.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_025`](../rules/zt_data_025.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Shodan-scan *.redis.cache.windows.net for 6379.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1595.001`  
**Enabled by:** [`zt_data_025`](../rules/zt_data_025.md)  

**Attacker gain:** Reachable Redis.


### Step 2 — KEYS * and GET session:*; harvest tokens.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** Session tokens for any app backed by this Redis.


## Blast radius

| | |
|---|---|
| Initial access | Internet scan. |
| Max privilege | User sessions. |
| Data at risk | Every key in Redis |
| Services at risk | Apps using this Redis for sessions/cache |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

