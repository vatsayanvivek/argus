# CHAIN-091 — Managed disk snapshot with overly-permissive SAS

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

A managed disk snapshot is exported via SAS URL with Read access + 7-day TTL. The URL ends up in a support ticket. Anyone with the URL downloads the full disk image — including OS, app secrets, and any cached database files.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_008`](../rules/zt_data_008.md) | Trigger |
| [`zt_data_012`](../rules/zt_data_012.md) | Trigger |

## Attack walkthrough

### Step 1 — Find the SAS URL in a leaked email / ticket.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_012`](../rules/zt_data_012.md)  

**Attacker gain:** Disk VHD URL.


### Step 2 — Download and mount the VHD locally.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1565.001`  
**Enabled by:** [`zt_data_008`](../rules/zt_data_008.md)  

**Attacker gain:** Full disk offline analysis — extract cached passwords, keys, data.


## Blast radius

| | |
|---|---|
| Initial access | Leaked SAS URL. |
| Max privilege | Full offline disk analysis. |
| Data at risk | Everything on the disk |
| Services at risk | Any app whose state was on the disk |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

