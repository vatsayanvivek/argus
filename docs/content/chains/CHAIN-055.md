# CHAIN-055 — Consent phishing via pre-authorized multi-tenant app

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

User consent to third-party apps is allowed tenant-wide without admin approval. An attacker registers a multi-tenant app requesting Mail.Read and Files.Read.All and sends phishing links. A single click grants the attacker's app persistent OAuth tokens — far more durable than a stolen password because tokens survive password resets.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_013`](../rules/zt_id_013.md) | Trigger |
| [`zt_id_014`](../rules/zt_id_014.md) | Trigger |

## Attack walkthrough

### Step 1 — Register a multi-tenant Entra app with privileged delegated scopes.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_013`](../rules/zt_id_013.md)  

**Attacker gain:** App artifact ready to request consent.


### Step 2 — Send phishing URL with /adminconsent or /authorize?prompt=consent.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1566.002`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

**Attacker gain:** Target clicks and grants consent.


### Step 3 — Use the refresh token to read mail, OneDrive, Teams messages for months.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

**Attacker gain:** Long-lived data access that survives password reset.


## Blast radius

| | |
|---|---|
| Initial access | Single user click. |
| Max privilege | Delegated scope — typically Mail.Read, Files.Read.All, User.Read. |
| Data at risk | Mailbox, OneDrive, Teams chats, Consented OAuth tokens |
| Services at risk | Microsoft 365 apps this user accesses |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

