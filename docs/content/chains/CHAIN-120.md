# CHAIN-120 — Function App with over-privileged Graph permission

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Function App is granted Directory.ReadWrite.All via its managed identity — the developer couldn't figure out the least-privilege scope. Any prompt-injection / template-injection / upstream-library-compromise against the function gives attackers tenant-wide directory write.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_002`](../rules/zt_wl_002.md) | Trigger |
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Exploit injection vuln in function HTTP handler.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_002`](../rules/zt_wl_002.md)  

**Attacker gain:** Code execution with function MI.


### Step 2 — Use MI's Directory.ReadWrite.All to create admin users.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

**Attacker gain:** Tenant admin persistence.


## Blast radius

| | |
|---|---|
| Initial access | Function-app vuln. |
| Max privilege | Tenant directory write. |
| Data at risk | All directory objects |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

