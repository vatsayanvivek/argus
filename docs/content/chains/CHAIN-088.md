# CHAIN-088 — MariaDB server with public endpoint + SSL off

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A MariaDB flexible server is reachable over the public internet and client SSL enforcement is disabled. An attacker who obtains the connection string gets clear-text credentials over the wire, and on-path adversaries can sniff traffic too.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_030`](../rules/zt_data_030.md) | Trigger |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Locate the connection string in an app repo.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_030`](../rules/zt_data_030.md)  

**Attacker gain:** Valid DB credentials.


### Step 2 — Connect over plaintext; read any table.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

**Attacker gain:** Database content + sniffable session for follow-on creds.


## Blast radius

| | |
|---|---|
| Initial access | Internet reachability + creds. |
| Max privilege | DB user role. |
| Data at risk | MariaDB databases |
| Services at risk | Dependent apps |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

