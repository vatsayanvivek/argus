# CHAIN-109 — Front Door without WAF + origin direct-exposure

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Front Door WAF is disabled and the origin (App Service or VM) also accepts direct internet traffic. Attackers discover the origin IP and attack it directly, bypassing any Front Door protection entirely.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_007`](../rules/zt_net_007.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — DNS history lookup or certificate-transparency search for the origin IP.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1596.003`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** Origin IP revealed.


### Step 2 — Attack origin directly; WAF never sees the traffic.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_net_007`](../rules/zt_net_007.md)  

**Attacker gain:** Unprotected origin exploitation.


## Blast radius

| | |
|---|---|
| Initial access | Public origin address. |
| Max privilege | Full origin compromise. |
| Data at risk | Origin app data |
| Services at risk | The 'protected' app |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

