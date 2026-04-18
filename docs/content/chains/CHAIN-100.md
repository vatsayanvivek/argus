# CHAIN-100 — Queue Storage without encryption-at-rest enforcement

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Queue Storage handles transient messages that often carry secrets (webhook payloads, user tokens). Encryption-at-rest is platform-default but key rotation is not enforced. A compromised Azure-layer subpoena + key theft yields historical queue content.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_005`](../rules/zt_data_005.md) | Trigger |
| [`zt_data_006`](../rules/zt_data_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise key rotation process or obtain KV access.

**Actor:** Advanced adversary  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_data_006`](../rules/zt_data_006.md)  

**Attacker gain:** Encryption key.


### Step 2 — Decrypt historical queue snapshots.

**Actor:** Adversary  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_data_005`](../rules/zt_data_005.md)  

**Attacker gain:** Past sensitive message content.


## Blast radius

| | |
|---|---|
| Initial access | Key management compromise. |
| Max privilege | Historical message decryption. |
| Data at risk | Past queue messages |
| Services at risk | Apps trusting queue confidentiality |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

