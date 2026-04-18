# CHAIN-145 — Bot Service app registration over-privileged

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure Bot Service registration has application permissions including User.Read.All and Channel.ReadAll — far more than needed for its normal Q&A chatbot function. A compromise of the bot's service principal yields tenant-wide read of user directory data.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_004`](../rules/zt_ai_004.md) | Trigger |
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise the bot's App Service via any web vuln.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_ai_004`](../rules/zt_ai_004.md)  

**Attacker gain:** Bot SP access.


### Step 2 — Call /users and /channels via Graph; exfil directory.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

**Attacker gain:** Entra directory read.


## Blast radius

| | |
|---|---|
| Initial access | Bot compromise. |
| Max privilege | Directory read + channel read. |
| Data at risk | Directory objects, Teams channels |
| Services at risk | Entra ID + Teams |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

