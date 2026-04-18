# CHAIN-162 — Traffic Manager with HTTP (unencrypted) endpoint in pool

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Traffic Manager profile includes at least one endpoint reachable over HTTP (port 80) not HTTPS. Failover to that endpoint drops TLS — users experience plaintext traffic to a 'secure' site during regional failures.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_007`](../rules/zt_int_007.md) | Trigger |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Primary endpoint fails; failover activates HTTP-only endpoint.

**Actor:** Infrastructure event  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_int_007`](../rules/zt_int_007.md)  

**Attacker gain:** User traffic routed to plaintext endpoint.


### Step 2 — Sniff or MITM user sessions.

**Actor:** On-path attacker  
**MITRE ATT&CK:** `T1557`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

**Attacker gain:** Credential capture during failover.


## Blast radius

| | |
|---|---|
| Initial access | Network path + failover event. |
| Max privilege | Credential theft. |
| Data at risk | Session cookies, auth headers |
| Services at risk | Traffic Manager consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

