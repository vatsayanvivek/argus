# CHAIN-176 — Recovery Vault without Multi-User Authorization

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Recovery Services Vault does not require a second approver for destructive operations (MUA disabled). A single compromised Backup Contributor can delete recovery points unilaterally — no approval workflow, no four-eyes control.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_001`](../rules/zt_bak_001.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Delete recovery points in a single action.

**Actor:** Compromised BC  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_bak_001`](../rules/zt_bak_001.md)  

**Attacker gain:** Unchallenged backup destruction.


### Step 2 — Proceed with ransomware knowing no backup recovery is possible.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Maximum ransomware leverage.


## Blast radius

| | |
|---|---|
| Initial access | Single compromised admin. |
| Max privilege | Irreversible backup deletion. |
| Data at risk | All backed-up workloads |
| Services at risk | Backup vault |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

