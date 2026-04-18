# CHAIN-077 — Key Vault soft-delete disabled + privileged RBAC

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Key Vault has soft-delete disabled. A privileged principal (or one compromised via any chain) deletes the vault. Every secret, cert, and key inside is gone permanently — the classic ransomware 'destroy the evidence' move, except for all cryptographic material.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_011`](../rules/zt_data_011.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Call DELETE /vaults/<name>.

**Actor:** Attacker with Contributor  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_011`](../rules/zt_data_011.md)  

**Attacker gain:** Vault purged; no recovery possible.


### Step 2 — Every app dependent on vault secrets fails.

**Actor:** Organisation  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Extended outage + forced key rotation for whatever was stored.


## Blast radius

| | |
|---|---|
| Initial access | Contributor on vault resource group. |
| Max privilege | Destructive — not escalation, but irrecoverable loss. |
| Data at risk | Every secret, cert, key in vault |
| Services at risk | Any app that pulls from the vault |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

