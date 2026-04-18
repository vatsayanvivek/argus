# CHAIN-097 — Legacy File Share SMB exposed outside trusted network

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure Files share uses SMB and is reachable over public IP addresses (firewall allows Azure services + public). Any compromised VM can mount the share with a captured account key.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_019`](../rules/zt_data_019.md) | Trigger |
| [`zt_net_005`](../rules/zt_net_005.md) | Trigger |

## Attack walkthrough

### Step 1 — net use \\account.file.core.windows.net\share /user:AZURE\account <key>.

**Actor:** Attacker with key  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_data_019`](../rules/zt_data_019.md)  

**Attacker gain:** Mounted share from anywhere.


### Step 2 — Walk share, exfiltrate, or deploy ransomware.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_net_005`](../rules/zt_net_005.md)  

**Attacker gain:** Mass file-server compromise.


## Blast radius

| | |
|---|---|
| Initial access | Captured key + SMB reachability. |
| Max privilege | Full share access. |
| Data at risk | Every file on the share |
| Services at risk | Azure Files consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

