# CHAIN-080 — SQL Server firewall 0.0.0.0-255.255.255.255

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure SQL Server has a firewall rule opening 0.0.0.0 to 255.255.255.255 and uses SQL authentication (no Entra integration). Any attacker with credentials — or success against a password-spray — has a direct connection string from anywhere on the internet.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_003`](../rules/zt_data_003.md) | Trigger |
| [`zt_data_004`](../rules/zt_data_004.md) | Trigger |

## Attack walkthrough

### Step 1 — Connect to <server>.database.windows.net:1433 from anywhere.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_data_003`](../rules/zt_data_003.md)  

**Attacker gain:** TCP reachability.


### Step 2 — Spray credentials against SQL auth.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1110.003`  
**Enabled by:** [`zt_data_004`](../rules/zt_data_004.md)  

**Attacker gain:** Valid SQL login.


### Step 3 — Read, alter, or xp_cmdshell-style escalation depending on role.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_data_003`](../rules/zt_data_003.md)  

**Attacker gain:** Database content + possible host access.


## Blast radius

| | |
|---|---|
| Initial access | Internet + credentials. |
| Max privilege | DB role + potential host escape. |
| Data at risk | All databases on the server |
| Services at risk | Azure SQL, Dependent apps |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

