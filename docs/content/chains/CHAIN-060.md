# CHAIN-060 — Managed identity with excessive subscription-scope role

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A resource's managed identity is assigned Contributor or higher at subscription scope. Any code execution on that resource (IMDS token) yields subscription-wide privilege. This is the bread-and-butter Azure privilege-escalation chain.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_008`](../rules/zt_id_008.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — curl the IMDS endpoint for a token scoped to management.azure.com.

**Actor:** Attacker on resource  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_id_008`](../rules/zt_id_008.md)  

**Attacker gain:** ARM token for the managed identity.


### Step 2 — Enumerate role assignments; identity holds Contributor on /subscriptions/<id>.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Confirmed subscription-scope privilege.


### Step 3 — Create new role assignment, new storage with anon access, exfiltrate VM disks.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Subscription takeover.


## Blast radius

| | |
|---|---|
| Initial access | Any RCE on the resource. |
| Max privilege | Subscription Contributor / Owner. |
| Data at risk | Every resource in the subscription |
| Services at risk | Azure RBAC subscription-wide |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

