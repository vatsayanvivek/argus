# CHAIN-152 — Azure Bot managed identity with over-broad Graph scope

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure Bot runs in Teams and the bot's service principal has Chat.Read.All and Files.Read.All delegated — the developer couldn't figure out per-conversation scopes. A compromised bot becomes a tenant-wide Teams eavesdropper.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_004`](../rules/zt_ai_004.md) | Trigger |
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Exploit bot endpoint or SP credential.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_ai_004`](../rules/zt_ai_004.md)  

**Attacker gain:** Bot SP access.


### Step 2 — Call Graph to read any chat in any tenant the bot joined.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

**Attacker gain:** Tenant-wide chat read.


## Blast radius

| | |
|---|---|
| Initial access | Bot compromise. |
| Max privilege | Tenant chat + file read. |
| Data at risk | Every Teams chat the bot has access to |
| Services at risk | Teams + OneDrive |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

