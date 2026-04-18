# CHAIN-180 — Backup agent version stale on prod VMs

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Backup agent (MARS / MABS) on prod VMs is running a version from 18 months ago. A published vulnerability in the agent itself lets an attacker escalate privilege on the host during backup operations.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_005`](../rules/zt_bak_005.md) | Trigger |
| [`zt_wl_008`](../rules/zt_wl_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Exploit backup agent vulnerability.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1068`  
**Enabled by:** [`zt_bak_005`](../rules/zt_bak_005.md)  

**Attacker gain:** Privilege escalation to SYSTEM on the VM.


### Step 2 — Read any file on the host; access MI tokens.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_008`](../rules/zt_wl_008.md)  

**Attacker gain:** Host + cloud compromise.


## Blast radius

| | |
|---|---|
| Initial access | Backup agent CVE. |
| Max privilege | Host SYSTEM. |
| Data at risk | Host filesystem + MI token |
| Services at risk | Any cloud resource the VM's MI can reach |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

